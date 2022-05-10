// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package bundle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/internal/json/patch"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/util"
)

// BundlesBasePath is the storage path used for storing bundle metadata
var BundlesBasePath = storage.MustParsePath("/system/bundles")

// Note: As needed these helpers could be memoized.

// ManifestStoragePath is the storage path used for the given named bundle manifest.
func ManifestStoragePath(name string) storage.Path {
	return append(BundlesBasePath, name, "manifest")
}

func namedBundlePath(name string) storage.Path {
	return append(BundlesBasePath, name)
}

func rootsPath(name string) storage.Path {
	return append(BundlesBasePath, name, "manifest", "roots")
}

func revisionPath(name string) storage.Path {
	return append(BundlesBasePath, name, "manifest", "revision")
}

func wasmModulePath(name string) storage.Path {
	return append(BundlesBasePath, name, "wasm")
}

func wasmEntrypointsPath(name string) storage.Path {
	return append(BundlesBasePath, name, "manifest", "wasm")
}

func metadataPath(name string) storage.Path {
	return append(BundlesBasePath, name, "manifest", "metadata")
}

// ReadBundleNamesFromStore will return a list of bundle names which have had their metadata stored.
func ReadBundleNamesFromStore(ctx context.Context, store storage.Store, txn storage.Transaction) ([]string, error) {
	value, err := store.Read(ctx, txn, BundlesBasePath)
	if err != nil {
		return nil, err
	}

	bundleMap, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("corrupt manifest roots")
	}

	bundles := make([]string, len(bundleMap))
	idx := 0
	for name := range bundleMap {
		bundles[idx] = name
		idx++
	}
	return bundles, nil
}

// WriteManifestToStore will write the manifest into the storage. This function is called when
// the bundle is activated.
func WriteManifestToStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string, manifest Manifest) error {
	return write(ctx, store, txn, ManifestStoragePath(name), manifest)
}

func write(ctx context.Context, store storage.Store, txn storage.Transaction, path storage.Path, value interface{}) error {
	if err := util.RoundTrip(&value); err != nil {
		return err
	}

	var dir []string
	if len(path) > 1 {
		dir = path[:len(path)-1]
	}

	if err := storage.MakeDir(ctx, store, txn, dir); err != nil {
		return err
	}

	return store.Write(ctx, txn, storage.AddOp, path, value)
}

// EraseManifestFromStore will remove the manifest from storage. This function is called
// when the bundle is deactivated.
func EraseManifestFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string) error {
	path := namedBundlePath(name)
	err := store.Write(ctx, txn, storage.RemoveOp, path, nil)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}
	return nil
}

func writeWasmModulesToStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string, b *Bundle) error {
	basePath := wasmModulePath(name)
	for _, wm := range b.WasmModules {
		path := append(basePath, wm.Path)
		err := write(ctx, store, txn, path, base64.StdEncoding.EncodeToString(wm.Raw))
		if err != nil {
			return err
		}
	}
	return nil
}

func eraseWasmModulesFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string) error {
	path := wasmModulePath(name)

	err := store.Write(ctx, txn, storage.RemoveOp, path, nil)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}
	return nil
}

// ReadWasmMetadataFromStore will read Wasm module resolver metadata from the store.
func ReadWasmMetadataFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string) ([]WasmResolver, error) {
	path := wasmEntrypointsPath(name)
	value, err := store.Read(ctx, txn, path)
	if err != nil {
		return nil, err
	}

	bs, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("corrupt wasm manifest data")
	}

	var wasmMetadata []WasmResolver

	err = util.UnmarshalJSON(bs, &wasmMetadata)
	if err != nil {
		return nil, fmt.Errorf("corrupt wasm manifest data")
	}

	return wasmMetadata, nil
}

// ReadWasmModulesFromStore will write Wasm module resolver metadata from the store.
func ReadWasmModulesFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string) (map[string][]byte, error) {
	path := wasmModulePath(name)
	value, err := store.Read(ctx, txn, path)
	if err != nil {
		return nil, err
	}

	encodedModules, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("corrupt wasm modules")
	}

	rawModules := map[string][]byte{}
	for path, enc := range encodedModules {
		encStr, ok := enc.(string)
		if !ok {
			return nil, fmt.Errorf("corrupt wasm modules")
		}
		bs, err := base64.StdEncoding.DecodeString(encStr)
		if err != nil {
			return nil, err
		}
		rawModules[path] = bs
	}
	return rawModules, nil
}

// ReadBundleRootsFromStore returns the roots in the specified bundle.
// If the bundle is not activated, this function will return
// storage NotFound error.
func ReadBundleRootsFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string) ([]string, error) {
	value, err := store.Read(ctx, txn, rootsPath(name))
	if err != nil {
		return nil, err
	}

	sl, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("corrupt manifest roots")
	}

	roots := make([]string, len(sl))

	for i := range sl {
		roots[i], ok = sl[i].(string)
		if !ok {
			return nil, fmt.Errorf("corrupt manifest root")
		}
	}

	return roots, nil
}

// ReadBundleRevisionFromStore returns the revision in the specified bundle.
// If the bundle is not activated, this function will return
// storage NotFound error.
func ReadBundleRevisionFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string) (string, error) {
	return readRevisionFromStore(ctx, store, txn, revisionPath(name))
}

func readRevisionFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, path storage.Path) (string, error) {
	value, err := store.Read(ctx, txn, path)
	if err != nil {
		return "", err
	}

	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("corrupt manifest revision")
	}

	return str, nil
}

// ReadBundleMetadataFromStore returns the metadata in the specified bundle.
// If the bundle is not activated, this function will return
// storage NotFound error.
func ReadBundleMetadataFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, name string) (map[string]interface{}, error) {
	return readMetadataFromStore(ctx, store, txn, metadataPath(name))
}

func readMetadataFromStore(ctx context.Context, store storage.Store, txn storage.Transaction, path storage.Path) (map[string]interface{}, error) {
	value, err := store.Read(ctx, txn, path)
	if err != nil {
		if storageErr, ok := err.(*storage.Error); ok && storageErr.Code == storage.NotFoundErr {
			return nil, nil
		}

		return nil, err
	}

	data, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("corrupt manifest metadata")
	}

	return data, nil
}

// ActivateOpts defines options for the Activate API call.
type ActivateOpts struct {
	Ctx          context.Context
	Store        storage.Store
	Txn          storage.Transaction
	TxnCtx       *storage.Context
	Compiler     *ast.Compiler
	Metrics      metrics.Metrics
	Bundles      map[string]*Bundle     // Optional
	ExtraModules map[string]*ast.Module // Optional

	legacy bool
}

// Activate the bundle(s) by loading into the given Store. This will load policies, data, and record
// the manifest in storage. The compiler provided will have had the polices compiled on it.
func Activate(opts *ActivateOpts) error {
	opts.legacy = false
	return activateBundles(opts)
}

// DeactivateOpts defines options for the Deactivate API call
type DeactivateOpts struct {
	Ctx         context.Context
	Store       storage.Store
	Txn         storage.Transaction
	BundleNames map[string]struct{}
}

// Deactivate the bundle(s). This will erase associated data, policies, and the manifest entry from the store.
func Deactivate(opts *DeactivateOpts) error {
	erase := map[string]struct{}{}
	for name := range opts.BundleNames {
		if roots, err := ReadBundleRootsFromStore(opts.Ctx, opts.Store, opts.Txn, name); err == nil {
			for _, root := range roots {
				erase[root] = struct{}{}
			}
		} else if !storage.IsNotFound(err) {
			return err
		}
	}
	_, err := eraseBundles(opts.Ctx, opts.Store, opts.Txn, opts.BundleNames, erase)
	return err
}

func activateBundles(opts *ActivateOpts) error {

	// Build collections of bundle names, modules, and roots to erase
	erase := map[string]struct{}{}
	names := map[string]struct{}{}
	deltaBundles := map[string]*Bundle{}
	snapshotBundles := map[string]*Bundle{}

	for name, b := range opts.Bundles {
		if b.Type() == DeltaBundleType {
			deltaBundles[name] = b
		} else {
			snapshotBundles[name] = b
			names[name] = struct{}{}

			if roots, err := ReadBundleRootsFromStore(opts.Ctx, opts.Store, opts.Txn, name); err == nil {
				for _, root := range roots {
					erase[root] = struct{}{}
				}
			} else if !storage.IsNotFound(err) {
				return err
			}

			// Erase data at new roots to prepare for writing the new data
			for _, root := range *b.Manifest.Roots {
				erase[root] = struct{}{}
			}
		}
	}

	// Before changing anything make sure the roots don't collide with any
	// other bundles that already are activated or other bundles being activated.
	err := hasRootsOverlap(opts.Ctx, opts.Store, opts.Txn, opts.Bundles)
	if err != nil {
		return err
	}

	if len(deltaBundles) != 0 {
		err := activateDeltaBundles(opts, deltaBundles)
		if err != nil {
			return err
		}
	}

	// Erase data and policies at new + old roots, and remove the old
	// manifests before activating a new snapshot bundle.
	remaining, err := eraseBundles(opts.Ctx, opts.Store, opts.Txn, names, erase)
	if err != nil {
		return err
	}

	for _, b := range snapshotBundles {
		// Write data from each new bundle into the store. Only write under the
		// roots contained in their manifest. This should be done *before* the
		// policies so that path conflict checks can occur.
		if err := writeData(opts.Ctx, opts.Store, opts.Txn, *b.Manifest.Roots, b.Data); err != nil {
			return err
		}
	}

	// Write and compile the modules all at once to avoid having to re-do work.
	remainingAndExtra := make(map[string]*ast.Module)
	for name, mod := range remaining {
		remainingAndExtra[name] = mod
	}
	for name, mod := range opts.ExtraModules {
		remainingAndExtra[name] = mod
	}

	err = writeModules(opts.Ctx, opts.Store, opts.Txn, opts.Compiler, opts.Metrics, snapshotBundles, remainingAndExtra, opts.legacy)
	if err != nil {
		return err
	}

	for name, b := range snapshotBundles {
		if err := writeManifestToStore(opts, name, b.Manifest); err != nil {
			return err
		}

		if err := writeWasmModulesToStore(opts.Ctx, opts.Store, opts.Txn, name, b); err != nil {
			return err
		}
	}

	return nil
}

func activateDeltaBundles(opts *ActivateOpts, bundles map[string]*Bundle) error {

	// Check that the manifest roots and wasm resolvers in the delta bundle
	// match with those currently in the store
	for name, b := range bundles {
		value, err := opts.Store.Read(opts.Ctx, opts.Txn, ManifestStoragePath(name))
		if err != nil {
			if storage.IsNotFound(err) {
				continue
			}
			return err
		}

		bs, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("corrupt manifest data: %w", err)
		}

		var manifest Manifest

		err = util.UnmarshalJSON(bs, &manifest)
		if err != nil {
			return fmt.Errorf("corrupt manifest data: %w", err)
		}

		if !b.Manifest.equalWasmResolversAndRoots(manifest) {
			return fmt.Errorf("delta bundle '%s' has wasm resolvers or manifest roots that are different from those in the store", name)
		}
	}

	for _, b := range bundles {
		err := applyPatches(opts.Ctx, opts.Store, opts.Txn, b.Patch.Data)
		if err != nil {
			return err
		}
	}

	if err := ast.CheckPathConflicts(opts.Compiler, storage.NonEmpty(opts.Ctx, opts.Store, opts.Txn)); len(err) > 0 {
		return err
	}

	for name, b := range bundles {
		if err := writeManifestToStore(opts, name, b.Manifest); err != nil {
			return err
		}
	}

	return nil
}

// erase bundles by name and roots. This will clear all policies and data at its roots and remove its
// manifest from storage.
func eraseBundles(ctx context.Context, store storage.Store, txn storage.Transaction, names map[string]struct{}, roots map[string]struct{}) (map[string]*ast.Module, error) {

	if err := eraseData(ctx, store, txn, roots); err != nil {
		return nil, err
	}

	remaining, err := erasePolicies(ctx, store, txn, roots)
	if err != nil {
		return nil, err
	}

	for name := range names {
		if err := EraseManifestFromStore(ctx, store, txn, name); err != nil && !storage.IsNotFound(err) {
			return nil, err
		}

		if err := LegacyEraseManifestFromStore(ctx, store, txn); err != nil && !storage.IsNotFound(err) {
			return nil, err
		}

		if err := eraseWasmModulesFromStore(ctx, store, txn, name); err != nil && !storage.IsNotFound(err) {
			return nil, err
		}
	}

	return remaining, nil
}

func eraseData(ctx context.Context, store storage.Store, txn storage.Transaction, roots map[string]struct{}) error {
	for root := range roots {
		path, ok := storage.ParsePathEscaped("/" + root)
		if !ok {
			return fmt.Errorf("manifest root path invalid: %v", root)
		}
		if len(path) > 0 {
			if err := store.Write(ctx, txn, storage.RemoveOp, path, nil); err != nil {
				if !storage.IsNotFound(err) {
					return err
				}
			}
		}
	}
	return nil
}

func erasePolicies(ctx context.Context, store storage.Store, txn storage.Transaction, roots map[string]struct{}) (map[string]*ast.Module, error) {

	ids, err := store.ListPolicies(ctx, txn)
	if err != nil {
		return nil, err
	}

	remaining := map[string]*ast.Module{}

	for _, id := range ids {
		bs, err := store.GetPolicy(ctx, txn, id)
		if err != nil {
			return nil, err
		}
		module, err := ast.ParseModule(id, string(bs))
		if err != nil {
			return nil, err
		}
		path, err := module.Package.Path.Ptr()
		if err != nil {
			return nil, err
		}
		deleted := false
		for root := range roots {
			if RootPathsContain([]string{root}, path) {
				if err := store.DeletePolicy(ctx, txn, id); err != nil {
					return nil, err
				}
				deleted = true
				break
			}
		}
		if !deleted {
			remaining[id] = module
		}
	}

	return remaining, nil
}

func writeManifestToStore(opts *ActivateOpts, name string, manifest Manifest) error {
	// Always write manifests to the named location. If the plugin is in the older style config
	// then also write to the old legacy unnamed location.
	if err := WriteManifestToStore(opts.Ctx, opts.Store, opts.Txn, name, manifest); err != nil {
		return err
	}

	if opts.legacy {
		if err := LegacyWriteManifestToStore(opts.Ctx, opts.Store, opts.Txn, manifest); err != nil {
			return err
		}
	}

	return nil
}

func writeData(ctx context.Context, store storage.Store, txn storage.Transaction, roots []string, data map[string]interface{}) error {
	for _, root := range roots {
		path, ok := storage.ParsePathEscaped("/" + root)
		if !ok {
			return fmt.Errorf("manifest root path invalid: %v", root)
		}
		if value, ok := lookup(path, data); ok {
			if len(path) > 0 {
				if err := storage.MakeDir(ctx, store, txn, path[:len(path)-1]); err != nil {
					return err
				}
			}
			if err := store.Write(ctx, txn, storage.AddOp, path, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeModules(ctx context.Context, store storage.Store, txn storage.Transaction, compiler *ast.Compiler, m metrics.Metrics, bundles map[string]*Bundle, extraModules map[string]*ast.Module, legacy bool) error {

	m.Timer(metrics.RegoModuleCompile).Start()
	defer m.Timer(metrics.RegoModuleCompile).Stop()

	modules := map[string]*ast.Module{}

	// preserve any modules already on the compiler
	for name, module := range compiler.Modules {
		modules[name] = module
	}

	// preserve any modules passed in from the store
	for name, module := range extraModules {
		modules[name] = module
	}

	// include all the new bundle modules
	for bundleName, b := range bundles {
		if legacy {
			for _, mf := range b.Modules {
				modules[mf.Path] = mf.Parsed
			}
		} else {
			for name, module := range b.ParsedModules(bundleName) {
				modules[name] = module
			}
		}
	}

	if compiler.Compile(modules); compiler.Failed() {
		return compiler.Errors
	}
	for bundleName, b := range bundles {
		for _, mf := range b.Modules {
			var path string

			// For backwards compatibility, in legacy mode, upsert policies to
			// the unprefixed path.
			if legacy {
				path = mf.Path
			} else {
				path = modulePathWithPrefix(bundleName, mf.Path)
			}

			if err := store.UpsertPolicy(ctx, txn, path, mf.Raw); err != nil {
				return err
			}
		}
	}
	return nil
}

func lookup(path storage.Path, data map[string]interface{}) (interface{}, bool) {
	if len(path) == 0 {
		return data, true
	}
	for i := 0; i < len(path)-1; i++ {
		value, ok := data[path[i]]
		if !ok {
			return nil, false
		}
		obj, ok := value.(map[string]interface{})
		if !ok {
			return nil, false
		}
		data = obj
	}
	value, ok := data[path[len(path)-1]]
	return value, ok
}

func hasRootsOverlap(ctx context.Context, store storage.Store, txn storage.Transaction, bundles map[string]*Bundle) error {
	collisions := map[string][]string{}
	allBundles, err := ReadBundleNamesFromStore(ctx, store, txn)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}

	allRoots := map[string][]string{}

	// Build a map of roots for existing bundles already in the system
	for _, name := range allBundles {
		roots, err := ReadBundleRootsFromStore(ctx, store, txn, name)
		if err != nil && !storage.IsNotFound(err) {
			return err
		}
		allRoots[name] = roots
	}

	// Add in any bundles that are being activated, overwrite existing roots
	// with new ones where bundles are in both groups.
	for name, bundle := range bundles {
		allRoots[name] = *bundle.Manifest.Roots
	}

	// Now check for each new bundle if it conflicts with any of the others
	for name, bundle := range bundles {
		for otherBundle, otherRoots := range allRoots {
			if name == otherBundle {
				// Skip the current bundle being checked
				continue
			}

			// Compare the "new" roots with other existing (or a different bundles new roots)
			for _, newRoot := range *bundle.Manifest.Roots {
				for _, otherRoot := range otherRoots {
					if RootPathsOverlap(newRoot, otherRoot) {
						collisions[otherBundle] = append(collisions[otherBundle], newRoot)
					}
				}
			}
		}
	}

	if len(collisions) > 0 {
		var bundleNames []string
		for name := range collisions {
			bundleNames = append(bundleNames, name)
		}
		return fmt.Errorf("detected overlapping roots in bundle manifest with: %s", bundleNames)
	}
	return nil
}

func applyPatches(ctx context.Context, store storage.Store, txn storage.Transaction, patches []PatchOperation) error {
	for _, pat := range patches {

		// construct patch path
		path, ok := patch.ParsePatchPathEscaped("/" + strings.Trim(pat.Path, "/"))
		if !ok {
			return fmt.Errorf("error parsing patch path")
		}

		var op storage.PatchOp
		switch pat.Op {
		case "upsert":
			op = storage.AddOp

			_, err := store.Read(ctx, txn, path[:len(path)-1])
			if err != nil {
				if !storage.IsNotFound(err) {
					return err
				}

				if err := storage.MakeDir(ctx, store, txn, path[:len(path)-1]); err != nil {
					return err
				}
			}
		case "remove":
			op = storage.RemoveOp
		case "replace":
			op = storage.ReplaceOp
		default:
			return fmt.Errorf("bad patch operation: %v", pat.Op)
		}

		// apply the patch
		if err := store.Write(ctx, txn, op, path, pat.Value); err != nil {
			return err
		}
	}

	return nil
}

// Helpers for the older single (unnamed) bundle style manifest storage.

// LegacyManifestStoragePath is the older unnamed bundle path for manifests to be stored.
// Deprecated: Use ManifestStoragePath and named bundles instead.
var legacyManifestStoragePath = storage.MustParsePath("/system/bundle/manifest")
var legacyRevisionStoragePath = append(legacyManifestStoragePath, "revision")

// LegacyWriteManifestToStore will write the bundle manifest to the older single (unnamed) bundle manifest location.
// Deprecated: Use WriteManifestToStore and named bundles instead.
func LegacyWriteManifestToStore(ctx context.Context, store storage.Store, txn storage.Transaction, manifest Manifest) error {
	return write(ctx, store, txn, legacyManifestStoragePath, manifest)
}

// LegacyEraseManifestFromStore will erase the bundle manifest from the older single (unnamed) bundle manifest location.
// Deprecated: Use WriteManifestToStore and named bundles instead.
func LegacyEraseManifestFromStore(ctx context.Context, store storage.Store, txn storage.Transaction) error {
	err := store.Write(ctx, txn, storage.RemoveOp, legacyManifestStoragePath, nil)
	if err != nil {
		return err
	}
	return nil
}

// LegacyReadRevisionFromStore will read the bundle manifest revision from the older single (unnamed) bundle manifest location.
// Deprecated: Use ReadBundleRevisionFromStore and named bundles instead.
func LegacyReadRevisionFromStore(ctx context.Context, store storage.Store, txn storage.Transaction) (string, error) {
	return readRevisionFromStore(ctx, store, txn, legacyRevisionStoragePath)
}

// ActivateLegacy calls Activate for the bundles but will also write their manifest to the older unnamed store location.
// Deprecated: Use Activate with named bundles instead.
func ActivateLegacy(opts *ActivateOpts) error {
	opts.legacy = true
	return activateBundles(opts)
}
