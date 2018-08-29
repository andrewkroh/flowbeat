// +build mage

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/magefile/mage/mg"
	"github.com/pkg/errors"
	"golang.org/x/tools/go/vcs"

	"github.com/elastic/beats/dev-tools/mage"
)

const beatsImport = "github.com/elastic/beats"

// BeatsCache is the local cache directory for any downloads. It defaults to
// $HOME/.beats.
var BeatsCache = mage.EnvOr("BEATS_CACHE", "")

// Used to compute a friendly filepath from a URL-shaped input.
var sanitizer = strings.NewReplacer("-", "--", ":", "-", "/", "-", "+", "-")

type DepGopkgLockData struct {
	Projects []PackageMeta `toml:"projects"`
}

type GoVendorData struct {
	Package []PackageMeta `json:"package"`
}

type PackageMeta struct {
	Name     string `toml:"name" json:"path"`
	Revision string
	Source   string `toml:"source" json:"origin"`
}

var syncFiles = []string{
	"libbeat/_meta/*",
	"libbeat/docs/version.asciidoc",
	"libbeat/processors/*/_meta/fields.yml",
	"libbeat/scripts/Makefile",
	"libbeat/scripts/*py",
	"libbeat/scripts/cmd/global_fields/main.go",
	"libbeat/tests/system/requirements.txt",
	"dev-tools/cmd",
	"dev-tools/packaging",
	"dev-tools/vendor/github.com/tsg/go-daemon",
}

func SyncTools() error {
	// Support reading both govendor and dep metadata.
	proj, err := readGopkgBeatsProject()
	if err != nil {
		log.Println("Tried reading golang/dep metadata:", err)
		proj, err = readGovendorBeatsProject()
	}
	if err != nil {
		log.Println("Tried reading govendor metadata:", err)
		return errors.New("failed to read project's vendor data")
	}
	log.Printf("Found %v project info in vendor: %+v", beatsImport, proj)

	srcDir, err := checkoutProject(proj)
	if err != nil {
		return err
	}

	return syncElasticBeatsTools(srcDir, ".elastic-beats")
}

func readGopkgBeatsProject() (*PackageMeta, error) {
	data, err := ioutil.ReadFile("Gopkg.lock")
	if err != nil {
		return nil, errors.Wrap(err, "failed to read Gopkg.lock")
	}

	var deps DepGopkgLockData
	if _, err := toml.Decode(string(data), &deps); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal Gopkg.lock data")
	}

	// Find github.com/elastic/beats.
	for _, project := range deps.Projects {
		if project.Name == beatsImport {
			return &project, nil
		}
	}
	return nil, errors.New(beatsImport + " was not found in Gopkg.lock")
}

func readGovendorBeatsProject() (*PackageMeta, error) {
	data, err := ioutil.ReadFile("vendor/vendor.json")
	if err != nil {
		return nil, errors.Wrap(err, "failed to read vendor/vendor.json")
	}

	var deps GoVendorData
	if err = json.Unmarshal(data, &deps); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal vendor.json data")
	}

	// Find github.com/elastic/beats.
	for _, pkg := range deps.Package {
		if pkg.Name == beatsImport+"/libbeat/common" {
			return &pkg, nil
		}
	}
	return nil, errors.New(beatsImport + " was not found in vendor.json")
}

func checkoutProject(p *PackageMeta) (string, error) {
	if p.Source == "" {
		p.Source = p.Name
	}

	// Determine the VCS info for the project's source.
	root, err := vcs.RepoRootForImportPath(p.Source, mg.Verbose())
	if err != nil {
		return "", errors.Wrapf(err, "failed to determine VCS info for %v", p.Source)
	}

	localDir, err := getRepoCacheDir(root.Repo)
	if err != nil {
		return "", err
	}
	log.Printf("Use repo cache at %v", localDir)

	// If it's not git then blow away our cache because we don't know how
	// to check the revision or update.
	if root.VCS.Name != "Git" {
		if err = os.RemoveAll(localDir); err != nil {
			return "", errors.Wrap(err, "failed to clear cached repo")
		}
	}

	// Check if we already have a checkout.
	if n := dirContentsSize(localDir); n <= 0 {
		// Do a full clone.
		err = root.VCS.CreateAtRev(localDir, root.Repo, p.Revision)
		if err != nil {
			return "", errors.Wrapf(err, "failed to checkout repo source '%v' "+
				"at revision %v to %v", p.Source, p.Revision, localDir)
		}
		return localDir, nil
	}

	// Git reset, fetch, checkout.

	// Clear any local changes.
	cmd := exec.Command("git", "reset", "--hard")
	cmd.Dir = localDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		return "", errors.Wrap(err, "git reset failed")
	}

	// Fetch.
	cmd = exec.Command("git", "fetch")
	cmd.Dir = localDir
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		return "", errors.Wrap(err, "git fetch failed")
	}

	// Checkout revision.
	cmd = exec.Command("git", "checkout", p.Revision)
	cmd.Dir = localDir
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		return "", errors.Wrap(err, "git checkout failed")
	}

	return localDir, nil
}

func dirContentsSize(dir string) int {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return -1
	}
	return len(files)
}

func syncElasticBeatsTools(srcDir, dstDir string) error {
	if err := os.RemoveAll(dstDir); err != nil {
		return errors.Wrap(err, "failed to clean destination elastic beats dir")
	}

	for _, path := range syncFiles {
		path = filepath.Join(srcDir, path)

		matches, err := filepath.Glob(path)
		if err != nil {
			return errors.Wrap(err, "glob failed")
		}

		for _, file := range matches {
			dstPath := strings.TrimPrefix(file, srcDir)
			dstPath = filepath.Join(dstDir, dstPath)

			err := mage.Copy(file, dstPath)
			if err != nil {
				return errors.Wrap(err, "failed to copy file")
			}
		}
	}

	return nil
}

func getRepoCacheDir(repo string) (string, error) {
	if BeatsCache == "" {
		// Try to find the home dir.
		var homeDir = []func() string{
			func() string { return os.Getenv("HOME") },
			func() string { return os.Getenv("HOMEPATH") },
			func() string {
				if usr, err := user.Current(); err == nil {
					return usr.HomeDir
				}
				return ""
			},
		}

		for _, f := range homeDir {
			if home := f(); home != "" {
				BeatsCache = filepath.Join(home, ".beats")
			}
		}

		if BeatsCache == "" {
			return "", errors.New("failed to determine repo cache dir (try " +
				"setting BEATS_CACHE)")
		}
	}

	if err := os.MkdirAll(BeatsCache, 0755); err != nil {
		return "", err
	}

	repoCacheDir := sanitizer.Replace(repo)
	return filepath.Join(BeatsCache, "sources", repoCacheDir), nil
}
