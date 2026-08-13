package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/istio-ecosystem/sail-operator/pkg/helm"
	"github.com/istio-ecosystem/sail-operator/pkg/install"
	resources "github.com/istio-ecosystem/sail-operator/resources"

	rbacv1 "k8s.io/api/rbac/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

const (
	generatedMarker = "# --- BEGIN GENERATED: do not edit below; run hack/update-sail-rbac.sh to regenerate ---"
	istiodChartPath = "charts/istiod"
	renderNamespace = "openshift-ingress"
	renderRelease   = "istiod"
)

type renderedRBACObject struct {
	Name  string
	Rules []rbacv1.PolicyRule
}

func NewSailRBACCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sail-rbac",
		Short: "Generate or verify istiod RBAC rules",
		Long:  "Renders the vendored istiod Helm chart and extracts ClusterRole/Role rules for the Sail Library ClusterRole manifest.",
	}
	cmd.AddCommand(newSailRBACGenerateCommand())
	cmd.AddCommand(newSailRBACVerifyCommand())
	return cmd
}

func newSailRBACGenerateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "generate <manifest-path>",
		Short: "Generate istiod RBAC rules into the manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			generated, err := generateFromAllVersions()
			if err != nil {
				return err
			}
			return writeManifest(args[0], generated)
		},
	}
}

func newSailRBACVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <manifest-path>",
		Short: "Verify the manifest matches the vendored charts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			generated, err := generateFromAllVersions()
			if err != nil {
				return err
			}
			return verifyManifest(args[0], generated)
		},
	}
}

func generateFromAllVersions() (string, error) {
	entries, err := resources.FS.ReadDir(".")
	if err != nil {
		return "", fmt.Errorf("reading resource FS root: %w", err)
	}

	var versions []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "v") {
			versions = append(versions, entry.Name())
		}
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("no versioned chart directories found")
	}
	sort.Strings(versions)

	// Render every version and collect RBAC objects. Use the latest
	// version's rendered output as the canonical source, but render
	// all versions to catch errors early.
	var latest string
	var latestObjects []renderedRBACObject
	for _, version := range versions {
		chartPath := version + "/" + istiodChartPath
		objects, err := renderAndExtract(chartPath)
		if err != nil {
			return "", fmt.Errorf("version %s: %w", version, err)
		}
		latest = version
		latestObjects = objects
	}

	return renderObjects(latest, latestObjects)
}

func renderAndExtract(chartPath string) ([]renderedRBACObject, error) {
	values := install.GatewayAPIDefaults(renderNamespace)
	helmValues := helm.FromValues(values)

	rendered, err := helm.RenderChart(resources.FS, chartPath, helmValues, renderNamespace, renderRelease)
	if err != nil {
		return nil, fmt.Errorf("rendering chart: %w", err)
	}

	// Sort template names for deterministic output
	var templateNames []string
	for name := range rendered {
		if isRBACTemplate(name) {
			templateNames = append(templateNames, name)
		}
	}
	sort.Strings(templateNames)

	var objects []renderedRBACObject
	for _, name := range templateNames {
		content := strings.TrimSpace(rendered[name])
		if content == "" {
			continue
		}
		parsed, err := extractRBACObjects(content)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		objects = append(objects, parsed...)
	}
	return objects, nil
}

func isRBACTemplate(name string) bool {
	base := name[strings.LastIndex(name, "/")+1:]
	return (strings.Contains(base, "clusterrole") && !strings.Contains(base, "binding")) ||
		base == "role.yaml"
}

func extractRBACObjects(content string) ([]renderedRBACObject, error) {
	var objects []renderedRBACObject
	for _, doc := range strings.Split(content, "---") {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		var cr rbacv1.ClusterRole
		if err := sigsyaml.Unmarshal([]byte(doc), &cr); err != nil {
			return nil, err
		}
		if cr.Kind != "ClusterRole" && cr.Kind != "Role" {
			continue
		}

		objects = append(objects, renderedRBACObject{
			Name:  fmt.Sprintf("%s/%s", strings.ToLower(cr.Kind), cr.Name),
			Rules: cr.Rules,
		})
	}
	return objects, nil
}

func renderObjects(version string, objects []renderedRBACObject) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Source: istiod Helm chart %s (rendered with GatewayAPIDefaults)\n", version)

	for _, obj := range objects {
		fmt.Fprintf(&sb, "\n# %s\n", obj.Name)
		out, err := sigsyaml.Marshal(obj.Rules)
		if err != nil {
			return "", fmt.Errorf("marshaling rules for %s: %w", obj.Name, err)
		}
		sb.Write(out)
	}

	return sb.String(), nil
}

func writeManifest(manifestPath string, generated string) error {
	existing, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}

	idx := strings.Index(string(existing), generatedMarker)
	if idx == -1 {
		return fmt.Errorf("marker %q not found in %s", generatedMarker, manifestPath)
	}

	header := string(existing[:idx])
	return os.WriteFile(manifestPath, []byte(header+generatedMarker+"\n\n"+generated), 0640)
}

func verifyManifest(manifestPath string, generated string) error {
	existing, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}

	idx := strings.Index(string(existing), generatedMarker)
	if idx == -1 {
		return fmt.Errorf("marker %q not found in %s", generatedMarker, manifestPath)
	}

	existingGenerated := strings.TrimSpace(string(existing)[idx+len(generatedMarker):])
	expectedGenerated := strings.TrimSpace(generated)

	if existingGenerated != expectedGenerated {
		return fmt.Errorf("generated RBAC is out of date; run hack/update-sail-rbac.sh to regenerate")
	}

	fmt.Println("Sail RBAC manifest is up to date.")
	return nil
}
