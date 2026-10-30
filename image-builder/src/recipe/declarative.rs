//! Recipes: a target's components in `specs/targets/<target>/components/<name>.toml`, and those
//! several targets build in `specs/components/<name>.toml`, which a target's file of the same name
//! overrides: merged over it, tables key by key, any other value (an array of steps included)
//! replacing the recipe's. A recipe using files (patches, configuration) is a directory,
//! `<name>/spec.toml` next to its files; overrides use their recipe's. `{<component>.<key>}`
//! names a target's own component by its name alone when no other target has one.
//!
//! A recipe is data: its metadata, sources, and its build as a list of steps of a fixed set of
//! kinds, each a call of the [`Build`] API (or of a policy helper, such as
//! [`Build::go_build`]). The result is a [`super::Plan`]. A component built from this
//! repository has `version = "workspace"` (the OS version), lists the repository paths it builds
//! from in `local` (hashed into its cache key), and its `cargo-build` steps name their Cargo
//! workspace's directory, `workspace`, whose crates the fetch phase downloads.
//!
//! # Values
//!
//! Strings only substitute, never compute. In `{...}`:
//!
//! - `{version}`, and `{vars.<key>}`: the recipe's `[vars]`;
//! - `{<component>.version}` and `{<component>.<key>}` (its `[exports]`), of the recipe
//!   `<component>`; `{<target>/<component>.<key>}` of the recipe as `<target>` overrides it.
//!
//! `[vars]` and `[exports]` hold strings or lists. A list item that is exactly `"{<key>}"` of a
//! list is replaced by that list's items. A value may hold locations, `{jobs}` and `{epoch}`:
//! they are resolved where the value is used.
//!
//! # Locations
//!
//! Where a step expects a location, or in a command argument (`DESTDIR={dest}`): `{dest}` (the
//! component's tree, installed at `/`: where the build systems install, unless told otherwise),
//! `{<source>}` (each source of `[sources]`: an archive, `.tar.*` or `.tgz`, extracted in
//! `work:<source>`; any other file as is), `{work:<path>}` (scratch space), `{out:<output>}` (an
//! output of the recipe),
//! `{dep:<target>/<component>}` (the tree of a component of a target) and
//! `{dep:<target>/<component>/<output>}` (its output), the dependency declarations,
//! `{secret:<file>}` (of `build/keys/`), `{image:<image>}` (a container image the recipe fills);
//! followed by an optional `/<path>`. Arguments also take `{jobs}` and `{epoch}`.
//!
//! `{{` and `}}` are literal braces. There are no conditionals or loops: steps take lists.
//!
//! Steps work in the extracted `src` source; `run` and `make` take another `dir` (a command without
//! one runs in `work:` when `src` is no archive). `cpe = "<vendor>:<product>"` is an application's
//! CPE 2.3 name at `version`.
//!
//! ```toml
//! version = "1.5.7"
//! kind = "library"
//! summary = "Zstandard compression library"
//! license = "BSD-3-Clause OR GPL-2.0-only"
//! homepage = "https://facebook.github.io/zstd/"
//! cpe = "facebook:zstandard"
//!
//! [sources.src]
//! url = "https://github.com/facebook/zstd/releases/download/v{version}/zstd-{version}.tar.gz"
//! sha256 = "eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3"
//!
//! [[build]]
//! make.args = ["PREFIX=/usr"]
//! make.install.targets = ["install", "PREFIX=/usr"]
//! ```

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use serde::Deserialize;
use toml::Value;

use super::{
    Arg, Base, Build, Cgo, ComponentName, ComponentType, ContainerImage, Loc, Meta, Mode, Plan,
    Recipe, RepoPath, Source, Unit, WORKSPACE_VERSION,
};
use crate::sha256::Sha256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct File {
    version: String,
    kind: ComponentType,
    summary: String,
    license: String,
    homepage: String,
    purl: Option<String>,
    /// `<vendor>:<product>` (an application's CPE 2.3 name, at `version`), or a whole name.
    cpe: Option<String>,
    /// Repository paths an in-tree component builds from (hashed into its cache key).
    #[serde(default)]
    local: Vec<RepoPath>,
    /// The components of its target it builds with (its environment's are always there).
    #[serde(default)]
    depends_on: Vec<ComponentName>,
    #[serde(default)]
    vars: toml::Table,
    #[serde(default)]
    exports: toml::Table,
    #[serde(default)]
    sources: BTreeMap<String, SourceFile>,
    /// "From scratch" container images the build fills, by name.
    #[serde(default)]
    images: BTreeMap<String, ImageFile>,
    #[serde(default)]
    build: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(untagged, expecting = "either url and sha256, or from")]
enum SourceFile {
    Download(Download),
    From(SharedSource),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Download {
    url: String,
    sha256: Sha256,
}

/// Another recipe's `src` source: `from = "<component>"`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedSource {
    from: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageFile {
    /// Absolute path in the image.
    entrypoint: String,
    /// `[uid, gid]`.
    user: (u32, u32),
}

/// One location (or pattern), or several.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Locations {
    One(String),
    Many(Vec<String>),
}

impl Locations {
    fn items(&self) -> &[String] {
        match self {
            Self::One(item) => std::slice::from_ref(item),
            Self::Many(items) => items,
        }
    }
}

/// A step: one [`Build`] call, or one per item of a list. Steps work in the extracted `src`
/// source, unless given a `dir` (commands without one run in `work:` when there is none).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
enum StepFile {
    /// Runs a command: `cmd` is the program and its arguments; `env` holds `[name, value]` pairs.
    Run {
        cmd: Vec<String>,
        dir: Option<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
    },
    /// Runs a command and writes its standard output to `into`.
    Capture {
        cmd: Vec<String>,
        into: String,
    },
    /// `make -j{jobs}` in `dir`, with `args`; then, with `install`, `make <targets>
    /// DESTDIR=<dest>`.
    Make {
        dir: Option<String>,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        install: Option<MakeInstall>,
    },
    /// `configure --prefix=<prefix> <args>` (`/usr` by default), `make` and `make install` into
    /// `dest`.
    #[serde(rename_all = "kebab-case")]
    Configure {
        /// `{dest}` by default.
        dest: Option<String>,
        prefix: Option<String>,
        #[serde(default)]
        args: Vec<String>,
        /// Runs `configure` in the source tree rather than in `work:build`.
        #[serde(default)]
        in_tree: bool,
        /// Its environment, `[name, value]` pairs.
        #[serde(default)]
        env: Vec<(String, String)>,
    },
    /// A CMake project, installed into `dest` (`{dest}` by default).
    Cmake {
        dest: Option<String>,
        #[serde(default)]
        args: Vec<String>,
    },
    /// A Meson project, installed into `{dest}`.
    Meson {
        #[serde(default)]
        args: Vec<String>,
    },
    /// Go commands (`[package, install path]`), built with the hardened defaults: pure Go, or
    /// with `cgo` linked statically against musl and, in `cgo.libraries`, other libraries'
    /// installed `/usr` tree.
    GoBuild {
        commands: Vec<(String, String)>,
        cgo: Option<CgoFile>,
        #[serde(default)]
        tags: Vec<String>,
        /// Link-time `-X` variables, `[name, value]`.
        #[serde(default)]
        vars: Vec<(String, String)>,
    },
    /// Builds the binaries (`[package, install path]`) of the Cargo workspace in `workspace` (a
    /// repository directory), offline and locked (its crates are fetched before, with network
    /// access).
    CargoBuild {
        workspace: RepoPath,
        binaries: Vec<(String, String)>,
    },
    /// Configures the kernel tree with `fragment` (a file of the recipe's directory), checking
    /// that every option made it into `.config`.
    KernelConfig {
        #[serde(default)]
        args: Vec<String>,
        fragment: RepoPath,
    },
    Mkdir(Locations),
    /// Installs one file, with `mode` (`0o644` by default).
    Install {
        from: String,
        to: String,
        mode: Option<Mode>,
    },
    /// Copies every match of `from` into the directory `into`.
    Copy {
        from: String,
        into: String,
    },
    /// The symbolic link `link`, pointing to `target`.
    Symlink {
        target: String,
        link: String,
    },
    /// Symbolic links in `dir`: `[name, target]`.
    Symlinks {
        dir: String,
        links: Vec<(String, String)>,
    },
    /// Removes the files or symbolic links matching each pattern (possibly none).
    Remove(Locations),
    /// Writes `contents`, or a `file` of the recipe's directory, as is or, as a `template`, with
    /// its values substituted.
    Write {
        to: String,
        #[serde(flatten)]
        content: WriteContent,
        mode: Option<Mode>,
        #[serde(default)]
        template: bool,
    },
    /// Applies patches, files of the recipe's directory, in order.
    Patch {
        files: Vec<RepoPath>,
    },
}

/// `make.install`: `make <targets> DESTDIR=<dest>` (`{dest}` by default).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MakeInstall {
    targets: Vec<String>,
    dest: Option<String>,
}

/// `go-build.cgo`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CgoFile {
    /// Other libraries' installed `/usr` tree.
    libraries: Option<String>,
}

/// What `write` writes: one of its keys.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WriteContent {
    Contents(String),
    /// A file of the recipe's directory.
    File(RepoPath),
}

/// The values of every recipe, resolved: `<recipe>.<key>` (`version`, `vars.<key>`,
/// `<export>`), where `<recipe>` is its id (`<component>`, or `<target>/<component>` for a
/// target's own). Their strings are templates holding no value: only locations, `{jobs}`,
/// `{epoch}` and escaped braces.
type Values = BTreeMap<String, Value>;

/// A component's recipe, loaded, before its plan is described.
struct Declarative<'a> {
    /// Its id in the values.
    id: String,
    meta: Meta,
    depends_on: Vec<ComponentName>,
    local: Vec<RepoPath>,
    sources: BTreeMap<String, Source>,
    images: BTreeMap<String, ContainerImage>,
    values: &'a Values,
    /// The files of the recipe's directory its steps use, by path.
    files: BTreeMap<String, String>,
    steps: Vec<StepFile>,
}

/// Every recipe of `specs/` (see the module documentation), its plan described: the components,
/// with the target that overrides each, if any.
pub fn load(specs: &Path) -> anyhow::Result<Vec<(Option<ComponentName>, Recipe)>> {
    let tables = read(&specs.join("components"))?;
    let mut recipes = BTreeMap::new();
    for (name, (entry, table)) in &tables {
        let id = name.to_string();
        recipes.insert(
            id.clone(),
            Unresolved::new(id, name, None, entry, table.clone())?,
        );
    }
    for (target, entry) in crate::specs::entries(&specs.join("targets"))? {
        let Some(overrides) = entry
            .dir
            .map(|dir| dir.join("components"))
            .filter(|dir| dir.is_dir())
        else {
            continue;
        };
        for (name, (own_entry, own)) in read(&overrides)? {
            let id = format!("{target}/{name}");
            let recipe = match tables.get(&name) {
                // An override of a shared recipe.
                Some((entry, base)) => {
                    ensure!(
                        own_entry.dir.is_none(),
                        "{}: an override has no directory: its files are its component's",
                        own_entry.spec.display()
                    );
                    let mut table = base.clone();
                    merge(&mut table, own);
                    let mut recipe =
                        Unresolved::new(id.clone(), &name, Some(&target), entry, table)?;
                    recipe.path = own_entry.spec;
                    recipe
                }
                // The target's own component.
                None => Unresolved::new(id.clone(), &name, Some(&target), &own_entry, own)?,
            };
            recipes.insert(id, recipe);
        }
    }
    // A target's own component is also named by its name alone, unless that is ambiguous.
    let mut aliases: BTreeMap<String, Option<String>> = BTreeMap::new();
    for recipe in recipes
        .values()
        .filter(|recipe| recipe.target.is_some() && !tables.contains_key(&recipe.name))
    {
        let alias = aliases
            .entry(recipe.name.to_string())
            .or_insert_with(|| Some(recipe.id.clone()));
        if alias.as_ref() != Some(&recipe.id) {
            *alias = None;
        }
    }
    let aliases: BTreeMap<String, String> = (aliases.into_iter())
        .filter_map(|(name, id)| Some((name, id?)))
        .collect();
    let recipes = Loaded { recipes, aliases };
    let values = resolve_all(&recipes)?;
    (recipes.recipes.values())
        .map(|recipe| {
            let described = Declarative::new(recipe, &recipes, &values)
                .and_then(Declarative::describe)
                .with_context(|| recipe.path.display().to_string())?;
            Ok((recipe.target.clone(), described))
        })
        .collect()
}

/// The recipes being loaded, by id, and the target-only ones by name too.
struct Loaded {
    recipes: BTreeMap<String, Unresolved>,
    /// `<component>` → `<target>/<component>`, for a component only one target has.
    aliases: BTreeMap<String, String>,
}

impl Loaded {
    /// The recipe `name` (an id, or a target-only component's name).
    fn get(&self, name: &str) -> Option<&Unresolved> {
        (self.recipes.get(name))
            .or_else(|| self.aliases.get(name).and_then(|id| self.recipes.get(id)))
    }
}

/// The recipes of `dir` ([`crate::specs`]), by name.
fn read(dir: &Path) -> anyhow::Result<BTreeMap<ComponentName, (crate::specs::Entry, toml::Table)>> {
    let mut tables = BTreeMap::new();
    for (name, entry) in crate::specs::entries(dir)? {
        let path = &entry.spec;
        ensure!(
            !RESERVED.contains(&name.as_str()),
            "{}: {name} is a reserved name",
            path.display()
        );
        let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        let table: toml::Table =
            toml::from_str(&text).with_context(|| path.display().to_string())?;
        tables.insert(name, (entry, table));
    }
    Ok(tables)
}

/// `own` over `base`: tables merge key by key, any other value replaces.
fn merge(base: &mut toml::Table, own: toml::Table) {
    for (key, value) in own {
        match (base.get_mut(&key), value) {
            (Some(Value::Table(base)), Value::Table(own)) => merge(base, own),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// Value namespaces, which cannot be component names.
const RESERVED: &[&str] = &["version", "vars", "jobs", "epoch"];

/// A recipe as read, its values not resolved yet.
struct Unresolved {
    /// `<name>`, or `<target>/<name>` for a target's override.
    id: String,
    name: ComponentName,
    /// The target overriding the recipe.
    target: Option<ComponentName>,
    /// The recipe file (the override's, for an override).
    path: PathBuf,
    /// The directory of the files it uses (`<name>/`, whether it exists or not).
    dir: PathBuf,
    file: File,
}

impl Unresolved {
    /// The recipe `table` of the component `entry`.
    fn new(
        id: String,
        name: &ComponentName,
        target: Option<&ComponentName>,
        entry: &crate::specs::Entry,
        table: toml::Table,
    ) -> anyhow::Result<Self> {
        let file = File::deserialize(table).with_context(|| entry.spec.display().to_string())?;
        let dir = (entry.dir.clone()).unwrap_or_else(|| entry.spec.with_extension(""));
        Ok(Self {
            id,
            name: name.clone(),
            target: target.cloned(),
            path: entry.spec.clone(),
            dir,
            file,
        })
    }
}

/// Resolves every recipe's values, each once, failing on a cycle.
fn resolve_all(recipes: &Loaded) -> anyhow::Result<Values> {
    let mut resolver = Resolver {
        recipes,
        values: BTreeMap::new(),
        resolving: Vec::new(),
    };
    for (name, recipe) in &recipes.recipes {
        resolver.get(&format!("{name}.version"))?;
        for key in recipe.file.vars.keys() {
            resolver.get(&format!("{name}.vars.{key}"))?;
        }
        for key in recipe.file.exports.keys() {
            ensure!(
                !matches!(key.as_str(), "version" | "vars") && !key.contains('.'),
                "{name}: invalid export name {key:?}"
            );
            resolver.get(&format!("{name}.{key}"))?;
        }
    }
    // A target-only component's values by its name alone too.
    let mut values = resolver.values;
    for (alias, id) in &recipes.aliases {
        let prefix = format!("{id}.");
        let named: Vec<(String, Value)> = (values.iter())
            .filter_map(|(key, value)| {
                Some((
                    format!("{alias}.{}", key.strip_prefix(&prefix)?),
                    value.clone(),
                ))
            })
            .collect();
        values.extend(named);
    }
    Ok(values)
}

struct Resolver<'a> {
    recipes: &'a Loaded,
    values: Values,
    /// The values being resolved, to report cycles.
    resolving: Vec<String>,
}

impl Resolver<'_> {
    /// The value `<component>.<key>`.
    fn get(&mut self, full: &str) -> anyhow::Result<Value> {
        if let Some(value) = self.values.get(full) {
            return Ok(value.clone());
        }
        ensure!(
            !self.resolving.iter().any(|key| key == full),
            "{{{full}}} depends on itself: {}",
            self.resolving.join(" → ")
        );
        self.resolving.push(full.to_owned());
        let value = self.compute(full).with_context(|| format!("{{{full}}}"));
        self.resolving.pop();
        let value = value?;
        self.values.insert(full.to_owned(), value.clone());
        Ok(value)
    }

    fn compute(&mut self, full: &str) -> anyhow::Result<Value> {
        let (component, key) = full.split_once('.').context("no key")?;
        let recipe =
            (self.recipes.get(component)).with_context(|| format!("unknown recipe {component}"))?;
        let file = &recipe.file;
        if key == "version" {
            if file.version == "workspace" {
                return Ok(Value::String(escape(WORKSPACE_VERSION)));
            }
            return Ok(Value::String(self.text(component, &file.version)?));
        }
        let raw_value = match key.strip_prefix("vars.") {
            Some(var) => file
                .vars
                .get(var)
                .with_context(|| format!("{component} has no vars.{var}"))?,
            None => {
                (file.exports.get(key)).with_context(|| format!("{component} exports no {key}"))?
            }
        };
        self.value(component, raw_value)
    }

    /// `value` (of `component`'s recipe) with its strings substituted and its lists spliced.
    fn value(&mut self, component: &str, value: &Value) -> anyhow::Result<Value> {
        Ok(match value {
            Value::String(text) => Value::String(self.text(component, text)?),
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items {
                    match self.splice(component, item)? {
                        Some(list) => out.extend(list),
                        None => out.push(self.value(component, item)?),
                    }
                }
                Value::Array(out)
            }
            _ => bail!("only strings and lists of them are values"),
        })
    }

    /// The items `item` stands for, if it is exactly the reference of a list.
    fn splice(&mut self, component: &str, item: &Value) -> anyhow::Result<Option<Vec<Value>>> {
        let Some(key) = list_reference(item) else {
            return Ok(None);
        };
        match self.lookup(component, key)? {
            Some(Value::Array(list)) => Ok(Some(list)),
            _ => Ok(None),
        }
    }

    fn text(&mut self, component: &str, text: &str) -> anyhow::Result<String> {
        Ok(template(tokens(text, &mut |key| {
            self.lookup(component, key)
        })?))
    }

    /// A value seen from `component`'s recipe, if `key` names one.
    fn lookup(&mut self, component: &str, key: &str) -> anyhow::Result<Option<Value>> {
        match qualify(component, key)? {
            None => Ok(None),
            Some(full) => self.get(&full).map(Some),
        }
    }
}

/// The key `"{<key>}"` an item consists of, if it does.
fn list_reference(item: &Value) -> Option<&str> {
    let text = item.as_str()?;
    let key = text.strip_prefix('{')?.strip_suffix('}')?;
    (!key.contains(['{', '}'])).then_some(key)
}

/// The value `key` names in the recipe `recipe` (its id), `<recipe>.<key>`, if it names one.
fn qualify(recipe: &str, key: &str) -> anyhow::Result<Option<String>> {
    Ok(Some(match key {
        "version" => format!("{recipe}.version"),
        _ => {
            let Some((head, rest)) = key.split_once('.') else {
                return Ok(None);
            };
            if head.contains(':') {
                return Ok(None);
            }
            match head {
                "vars" => format!("{recipe}.vars.{rest}"),
                _ => {
                    ensure!(
                        !rest.starts_with("vars."),
                        "{{{key}}}: vars are private to their recipe"
                    );
                    key.to_owned()
                }
            }
        }
    }))
}

/// A piece of a string, its values substituted.
#[derive(Debug, PartialEq)]
enum Token {
    Text(String),
    /// A location reference.
    Location(String),
    Jobs,
    Epoch,
}

/// The tokens of `text`, values substituted with `lookup` (which returns `None` for a key that
/// is not a value).
fn tokens(
    text: &str,
    lookup: &mut dyn FnMut(&str) -> anyhow::Result<Option<Value>>,
) -> anyhow::Result<Vec<Token>> {
    let mut out = Vec::new();
    let mut literal = String::new();
    let mut rest = text;
    while let Some(i) = rest.find(['{', '}']) {
        literal.push_str(&rest[..i]);
        let (brace, after) = (&rest[i..i + 1], &rest[i + 1..]);
        if after.starts_with(brace) {
            literal.push_str(brace);
            rest = &after[1..];
            continue;
        }
        ensure!(brace == "{", "unbalanced '}}' in {text:?}");
        let end = after
            .find('}')
            .with_context(|| format!("unclosed '{{' in {text:?}"))?;
        let key = &after[..end];
        ensure!(
            !key.is_empty() && !key.contains('{'),
            "invalid '{{{key}}}' in {text:?}"
        );
        rest = &after[end + 1..];
        let token = match key {
            "jobs" => Token::Jobs,
            "epoch" => Token::Epoch,
            _ => match lookup(key)? {
                Some(Value::String(value)) => {
                    // A resolved value: a template holding no value.
                    for token in tokens(&value, &mut |_| Ok(None))? {
                        match token {
                            Token::Text(text) => literal.push_str(&text),
                            token => {
                                if !literal.is_empty() {
                                    out.push(Token::Text(std::mem::take(&mut literal)));
                                }
                                out.push(token);
                            }
                        }
                    }
                    continue;
                }
                // Values are strings or lists.
                Some(_) => {
                    bail!(
                        "{{{key}}} is a list: a list is used as a whole item of a list, not in {text:?}"
                    )
                }
                None => Token::Location(key.to_owned()),
            },
        };
        if !literal.is_empty() {
            out.push(Token::Text(std::mem::take(&mut literal)));
        }
        out.push(token);
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        out.push(Token::Text(literal));
    }
    Ok(out)
}

/// `tokens` as a template: text escaped, locations, `{jobs}` and `{epoch}` as written.
fn template(tokens: Vec<Token>) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            Token::Text(text) => out.push_str(&escape(&text)),
            Token::Location(key) => out.push_str(&format!("{{{key}}}")),
            Token::Jobs => out.push_str("{jobs}"),
            Token::Epoch => out.push_str("{epoch}"),
        }
    }
    out
}

fn escape(text: &str) -> String {
    text.replace('{', "{{").replace('}', "}}")
}

/// The text of a resolved value, which must hold no location, `{jobs}` or `{epoch}`.
fn final_text(value: &Value) -> anyhow::Result<String> {
    let template = value.as_str().context("not a string")?;
    plain(template, tokens(template, &mut |_| Ok(None))?)
}

/// The text of `tokens`, which must hold no location, `{jobs}` or `{epoch}`.
fn plain(text: &str, tokens: Vec<Token>) -> anyhow::Result<String> {
    let mut out = String::new();
    for token in tokens {
        match token {
            Token::Text(t) => out.push_str(&t),
            Token::Location(key) => bail!("unknown value {{{key}}} in {text:?}"),
            Token::Jobs | Token::Epoch => {
                bail!("{text:?}: {{jobs}} and {{epoch}} are for commands")
            }
        }
    }
    Ok(out)
}

/// `path` if relative, without empty, `.` or `..` segments.
fn checked(path: &str) -> anyhow::Result<&str> {
    ensure!(
        !path.is_empty()
            && path
                .split('/')
                .all(|segment| !matches!(segment, "" | "." | "..")),
        "{path:?} is not a relative path without '.' or '..'"
    );
    Ok(path)
}

/// The CPE 2.3 name `cpe` stands for: `<vendor>:<product>` of an application at `version`, or a
/// whole `cpe:2.3:...` name.
fn cpe_of(cpe: &str, version: &str) -> anyhow::Result<String> {
    if cpe.starts_with("cpe:") {
        return Ok(cpe.to_owned());
    }
    let (vendor, product) = (cpe.split_once(':'))
        .filter(|(vendor, product)| {
            !vendor.is_empty() && !product.is_empty() && !product.contains(':')
        })
        .with_context(|| {
            format!("cpe {cpe:?}: `<vendor>:<product>`, or a whole `cpe:2.3:` name")
        })?;
    Ok(format!(
        "cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    ))
}

/// A value seen from `component`'s recipe, from the resolved `values`.
fn lookup(values: &Values, component: &str, key: &str) -> anyhow::Result<Option<Value>> {
    match qualify(component, key)? {
        None => Ok(None),
        Some(full) => (values.get(&full).cloned())
            .with_context(|| format!("unknown value {{{key}}}"))
            .map(Some),
    }
}

/// `value` with its list references spliced (strings stay as they are, for the steps).
fn splice(values: &Values, component: &str, value: &Value) -> anyhow::Result<Value> {
    Ok(match value {
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                if let Some(key) = list_reference(item)
                    && let Some(Value::Array(list)) = lookup(values, component, key)?
                {
                    out.extend(list);
                    continue;
                }
                out.push(splice(values, component, item)?);
            }
            Value::Array(out)
        }
        Value::Table(table) => Value::Table(
            table
                .iter()
                .map(|(k, v)| Ok((k.clone(), splice(values, component, v)?)))
                .collect::<anyhow::Result<_>>()?,
        ),
        _ => value.clone(),
    })
}

impl<'a> Declarative<'a> {
    fn new(recipe: &Unresolved, recipes: &Loaded, values: &'a Values) -> anyhow::Result<Self> {
        let name = recipe.id.as_str();
        let file = &recipe.file;
        let text = |text: &str| plain(text, tokens(text, &mut |key| lookup(values, name, key))?);

        let mut sources = BTreeMap::new();
        for (key, source) in &file.sources {
            ensure!(
                key != "dest",
                "sources.dest: `{{dest}}` is the component's tree"
            );
            checked(key)
                .with_context(|| format!("sources.{key}: a source name is a directory name"))?;
            let resolved = match source {
                SourceFile::From(SharedSource { from }) => {
                    let other = (recipes.get(from))
                        .with_context(|| format!("sources.{key}: unknown {from}"))?;
                    Declarative::source_of(other, "src", values)?
                }
                SourceFile::Download(_) => Declarative::source_of(recipe, key, values)?,
            };
            sources.insert(key.clone(), resolved);
        }

        let mut images = BTreeMap::new();
        for (image, spec) in &file.images {
            let image_name: ComponentName =
                image.parse().with_context(|| format!("images.{image}"))?;
            ensure!(
                spec.entrypoint.starts_with('/'),
                "images.{image}: the entrypoint is absolute"
            );
            images.insert(
                image.clone(),
                ContainerImage {
                    name: image_name,
                    entrypoint: spec.entrypoint.clone(),
                    user: spec.user,
                },
            );
        }

        let mut build = Vec::new();
        for (i, step) in file.build.iter().enumerate() {
            let step: StepFile = splice(values, name, step)?
                .try_into()
                .with_context(|| format!("build step {}", i + 1))?;
            build.push(step);
        }

        let mut files = BTreeMap::new();
        for step in &build {
            let names: &[RepoPath] = match step {
                StepFile::Patch { files, .. } => files,
                StepFile::Write {
                    content: WriteContent::File(file),
                    ..
                }
                | StepFile::KernelConfig { fragment: file, .. } => std::slice::from_ref(file),
                _ => &[],
            };
            for name in names {
                let path = recipe.dir.join(name);
                let contents =
                    std::fs::read_to_string(&path).with_context(|| path.display().to_string())?;
                files.insert(name.as_str().to_owned(), contents);
            }
        }

        let version = final_text(&values[&format!("{name}.version")]).context("version")?;
        ensure!(!version.is_empty(), "empty version");
        let purl = match &file.purl {
            Some(purl) => text(purl).context("purl")?,
            None => format!("pkg:generic/{}@{version}", recipe.name),
        };
        ensure!(purl.starts_with("pkg:"), "purl must start with \"pkg:\"");
        let cpe = file
            .cpe
            .as_deref()
            .map(|cpe| cpe_of(&text(cpe)?, &version))
            .transpose()?;
        let meta = Meta {
            name: recipe.name.clone(),
            version,
            kind: file.kind,
            summary: file.summary.clone(),
            license: file.license.clone(),
            homepage: file.homepage.clone(),
            purl,
            cpe,
        };
        Ok(Self {
            id: recipe.id.clone(),
            meta,
            depends_on: file.depends_on.clone(),
            local: file.local.clone(),
            sources,
            images,
            values,
            files,
            steps: build,
        })
    }

    /// The source `key` of `recipe`'s recipe.
    fn source_of(recipe: &Unresolved, key: &str, values: &Values) -> anyhow::Result<Source> {
        let name = recipe.id.as_str();
        let source = (recipe.file.sources.get(key))
            .with_context(|| format!("{name} has no source {key}"))?;
        let SourceFile::Download(Download { url, sha256 }) = source else {
            bail!("sources.{key} of {name} is not a download");
        };
        let url = plain(url, tokens(url, &mut |k| lookup(values, name, k))?)?;
        Ok(Source {
            url,
            sha256: *sha256,
        })
    }

    /// The recipe, its plan described.
    fn describe(self) -> anyhow::Result<Recipe> {
        let plan = Plan::describe(|b| self.fetch(b), |b| self.build(b))?;
        Ok(Recipe {
            meta: self.meta,
            local: self.local,
            depends_on: self.depends_on,
            plan,
        })
    }

    /// Steps run with network access before the build, for lockfile-verified downloads only: the
    /// crates of each Cargo workspace built.
    fn fetch(&self, b: &mut Build) {
        let workspaces: BTreeSet<&RepoPath> = (self.steps.iter())
            .filter_map(|step| match step {
                StepFile::CargoBuild { workspace, .. } => Some(workspace),
                _ => None,
            })
            .collect();
        for workspace in workspaces {
            b.cargo_fetch(workspace);
        }
    }

    /// The build, run without network access. It starts with its sources: archives (`.tar.*`,
    /// `.tgz`) extracted, other files as they are.
    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        let mut scope = Scope {
            recipe: self,
            locations: BTreeMap::new(),
        };
        for (name, source) in &self.sources {
            let loc = if source.is_archive() {
                b.unpack(source, name)
            } else {
                b.source(source)
            };
            scope.locations.insert(name.clone(), loc);
        }
        for (i, step) in self.steps.iter().enumerate() {
            scope
                .step(b, step)
                .with_context(|| format!("build step {} ({step:?})", i + 1))?;
        }
        Ok(())
    }
}

/// The recipe and the locations bound so far.
struct Scope<'a> {
    recipe: &'a Declarative<'a>,
    locations: BTreeMap<String, Loc>,
}

impl Scope<'_> {
    fn tokens(&self, text: &str) -> anyhow::Result<Vec<Token>> {
        let recipe = self.recipe;
        tokens(text, &mut |key| lookup(recipe.values, &recipe.id, key))
    }

    fn text(&self, text: &str) -> anyhow::Result<String> {
        plain(text, self.tokens(text)?)
    }

    fn texts(&self, texts: &[String]) -> anyhow::Result<Vec<String>> {
        texts.iter().map(|text| self.text(text)).collect()
    }

    fn pairs(&self, pairs: &[(String, String)]) -> anyhow::Result<Vec<(String, String)>> {
        (pairs.iter())
            .map(|(a, b)| Ok((self.text(a)?, self.text(b)?)))
            .collect()
    }

    /// The location `{key}`, then `suffix` (`/<path>`) if not empty.
    fn location(&self, b: &mut Build, key: &str, suffix: &str) -> anyhow::Result<Loc> {
        let base = match key.split_once(':') {
            None if key == "dest" => b.root("/"),
            Some(("work", path)) => b.work(checked(path)?),
            Some(("out", name)) => b.output(name),
            Some(("dep", reference)) => {
                let mut parts = reference.splitn(3, '/');
                let (Some(target), Some(component)) = (parts.next(), parts.next()) else {
                    bail!(
                        "{{{key}}}: `dep:<target>/<component>` or `dep:<target>/<component>/<output>`"
                    );
                };
                let unit = Unit {
                    target: target.parse()?,
                    component: component.parse()?,
                };
                b.input(&unit, parts.next())
            }
            Some(("secret", name)) => b.secret(name),
            Some(("image", name)) => {
                let image = (self.recipe.images.get(name))
                    .with_context(|| format!("{{{key}}}: no such image"))?;
                b.container_image(image)
            }
            Some(_) => bail!("unknown location {{{key}}}"),
            None => (self.locations.get(key).cloned())
                .with_context(|| format!("no location {{{key}}} is bound yet"))?,
        };
        Ok(match suffix.strip_prefix('/') {
            None if suffix.is_empty() => base,
            None => bail!("{{{key}}}{suffix}: a location is followed by `/<path>` only"),
            Some(path) => base.join(checked(path)?),
        })
    }

    /// The extracted `src` source, if there is one.
    fn source_tree(&self) -> Option<Loc> {
        (self.locations.get("src"))
            .filter(|src| *src.base() == Base::Work)
            .cloned()
    }

    /// The extracted `src` source, which a step works in.
    fn src(&self) -> anyhow::Result<Loc> {
        self.source_tree()
            .context("no extracted `src` source to work in")
    }

    /// Where a build system installs: `dest`, or the component's tree.
    fn dest(&self, b: &mut Build, dest: Option<&str>) -> anyhow::Result<Loc> {
        self.loc(b, dest.unwrap_or("{dest}"))
    }

    /// A field holding one location.
    fn loc(&self, b: &mut Build, text: &str) -> anyhow::Result<Loc> {
        match self.tokens(text)?.as_slice() {
            [Token::Location(key)] => self.location(b, key, ""),
            [Token::Location(key), Token::Text(suffix)]
                if !suffix.contains(char::is_whitespace) =>
            {
                self.location(b, key, suffix)
            }
            _ => bail!(
                "{text:?} is not a location (`{{dest}}`, `{{src}}`, `{{work:path}}`..., then `/path`)"
            ),
        }
    }

    /// A command argument: text, values, locations, `{jobs}` and `{epoch}`.
    fn arg(&self, b: &mut Build, text: &str) -> anyhow::Result<Arg> {
        let mut arg = Arg::default();
        let mut tokens = self.tokens(text)?.into_iter().peekable();
        while let Some(token) = tokens.next() {
            arg = match token {
                Token::Text(text) => arg.concat(text),
                Token::Jobs => arg.concat(Arg::jobs()),
                Token::Epoch => arg.concat(Arg::epoch()),
                Token::Location(key) => {
                    // The path right after it, up to a space.
                    let mut suffix = String::new();
                    if let Some(Token::Text(next)) = tokens.peek_mut()
                        && next.starts_with('/')
                    {
                        let end = next.find(char::is_whitespace).unwrap_or(next.len());
                        suffix = next[..end].to_owned();
                        next.replace_range(..end, "");
                        if next.is_empty() {
                            tokens.next();
                        }
                    }
                    arg.concat(self.location(b, &key, &suffix)?)
                }
            };
        }
        Ok(if arg.pieces().is_empty() {
            Arg::from("")
        } else {
            arg
        })
    }

    fn args(&self, b: &mut Build, texts: &[String]) -> anyhow::Result<Vec<Arg>> {
        texts.iter().map(|text| self.arg(b, text)).collect()
    }

    fn env<'e>(
        &self,
        b: &mut Build,
        env: &'e [(String, String)],
    ) -> anyhow::Result<Vec<(&'e str, Arg)>> {
        env.iter()
            .map(|(key, value)| Ok((key.as_str(), self.arg(b, value)?)))
            .collect()
    }

    /// A command: its program and arguments, directory and environment.
    fn command<'b>(
        &self,
        b: &'b mut Build,
        cmd: &[String],
        dir: Option<&str>,
        env: &[(String, String)],
    ) -> anyhow::Result<super::Cmd<'b>> {
        let (program, args) = cmd.split_first().context("empty command")?;
        let program = self.arg(b, program)?;
        let dir = match dir {
            Some(dir) => Some(self.loc(b, dir)?),
            None => self.source_tree(),
        };
        let args = self.args(b, args)?;
        let env = self.env(b, env)?;
        let mut command = b.cmd(program).args(args);
        if let Some(dir) = &dir {
            command = command.dir(dir);
        }
        for (key, value) in env {
            command = command.env(key, value);
        }
        Ok(command)
    }

    fn step(&self, b: &mut Build, step: &StepFile) -> anyhow::Result<()> {
        let recipe = self.recipe;
        match step {
            StepFile::Run { cmd, dir, env } => self.command(b, cmd, dir.as_deref(), env)?.run(),
            StepFile::Capture { cmd, into } => {
                let into = self.loc(b, into)?;
                self.command(b, cmd, None, &[])?.capture(&into);
            }
            StepFile::Make {
                dir,
                args,
                env,
                install,
            } => {
                let dir = match dir {
                    Some(dir) => self.loc(b, dir)?,
                    None => self.src()?,
                };
                let args = self.args(b, args)?;
                let env = self.env(b, env)?;
                let mut command = b.make(&dir).args(args);
                for (key, value) in env {
                    command = command.env(key, value);
                }
                command.run();
                let Some(MakeInstall { targets, dest }) = install else {
                    return Ok(());
                };
                ensure!(!targets.is_empty(), "make.install.targets: at least one");
                let targets = self.texts(targets)?;
                let dest = self.dest(b, dest.as_deref())?;
                b.make_install(&dir, &dest, targets);
            }
            StepFile::Configure {
                dest,
                prefix,
                args,
                in_tree,
                env,
            } => {
                let src = self.src()?;
                let prefix = match prefix {
                    Some(prefix) => self.text(prefix)?,
                    None => "/usr".to_owned(),
                };
                let dest = self.dest(b, dest.as_deref())?;
                let args = self.texts(args)?;
                let env = self.pairs(env)?;
                // Out of the source tree, unless the package cannot build elsewhere.
                let dir = if *in_tree {
                    src.clone()
                } else {
                    let dir = b.work("build");
                    b.mkdir(&dir);
                    dir
                };
                b.configure_make(&src, &dir, &dest, &prefix, args, env);
            }
            StepFile::Cmake { dest, args } => {
                let src = self.src()?;
                let dest = self.dest(b, dest.as_deref())?;
                let args = self.texts(args)?;
                b.cmake_build(&src, &dest, args);
            }
            StepFile::Meson { args } => {
                let src = self.src()?;
                let dest = b.root("/");
                let args = self.texts(args)?;
                b.meson_build(&src, &dest, args);
            }
            StepFile::GoBuild {
                commands,
                cgo,
                tags,
                vars,
            } => {
                let tree = self.src()?;
                let cgo = match cgo {
                    None => Cgo::Disabled,
                    Some(CgoFile { libraries }) => Cgo::Enabled {
                        libraries: libraries.as_deref().map(|l| self.loc(b, l)).transpose()?,
                    },
                };
                let tags = self.texts(tags)?;
                let vars = self.pairs(vars)?;
                b.go_build(&tree, &self.pairs(commands)?, &cgo, &tags, &vars);
            }
            StepFile::CargoBuild {
                workspace,
                binaries,
            } => b.cargo_build(workspace, &self.pairs(binaries)?),
            StepFile::KernelConfig { args, fragment } => {
                let tree = self.src()?;
                let args = self.texts(args)?;
                b.kernel_config(&tree, &args, &recipe.files[fragment.as_str()]);
            }
            StepFile::Mkdir(dirs) => {
                for dir in dirs.items() {
                    let dir = self.loc(b, dir)?;
                    b.mkdir(&dir);
                }
            }
            StepFile::Install { from, to, mode } => {
                let (from, to) = (self.loc(b, from)?, self.loc(b, to)?);
                b.install(&from, &to, mode.unwrap_or(Mode::FILE));
            }
            StepFile::Copy { from, into } => {
                let (from, into) = (self.loc(b, from)?, self.loc(b, into)?);
                b.copy(&from, &into);
            }
            StepFile::Symlink { target, link } => {
                let target = self.text(target)?;
                let link = self.loc(b, link)?;
                b.symlink(&target, &link);
            }
            StepFile::Symlinks { dir, links } => {
                let dir = self.loc(b, dir)?;
                for (name, target) in links {
                    b.symlink(&self.text(target)?, &dir.join(checked(&self.text(name)?)?));
                }
            }
            StepFile::Remove(patterns) => {
                for pattern in patterns.items() {
                    let pattern = self.loc(b, pattern)?;
                    b.remove(&pattern);
                }
            }
            StepFile::Write {
                to,
                content,
                mode,
                template,
            } => {
                let to = self.loc(b, to)?;
                let contents = match content {
                    WriteContent::Contents(contents) => contents,
                    WriteContent::File(file) => &recipe.files[file.as_str()],
                };
                let contents = if *template {
                    self.text(contents)?
                } else {
                    contents.clone()
                };
                b.write(&to, contents, mode.unwrap_or(Mode::FILE));
            }
            StepFile::Patch { files } => {
                let tree = self.src()?;
                for path in files {
                    let path = path.as_str();
                    b.patch(&tree, path, &recipe.files[path]);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "version = \"1.0\"\nkind = \"library\"\nsummary = \"s\"\nlicense = \"MIT\"\n\
                          homepage = \"https://example.org\"\n";
    const SHA: &str = "eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3";

    /// Loads recipes from `(id, text)` pairs (`<name>`, or `<target>/<name>` for a target's
    /// override), in a temporary `specs/`, by id.
    fn load_all(recipes: &[(&str, &str)]) -> anyhow::Result<BTreeMap<String, Recipe>> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("components")).unwrap();
        std::fs::create_dir_all(dir.path().join("targets")).unwrap();
        for (id, text) in recipes {
            let path = match id.split_once('/') {
                Some((target, name)) => dir
                    .path()
                    .join(format!("targets/{target}/components/{name}.toml")),
                None => dir.path().join(format!("components/{id}.toml")),
            };
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
            if let Some((target, _)) = id.split_once('/') {
                std::fs::write(dir.path().join(format!("targets/{target}/spec.toml")), "").unwrap();
            }
        }
        load(dir.path())?
            .into_iter()
            .map(|(target, recipe)| {
                let id = match target {
                    Some(target) => format!("{target}/{}", recipe.name()),
                    None => recipe.name().to_string(),
                };
                Ok((id, recipe))
            })
            .collect()
    }

    fn source() -> String {
        format!(
            "[sources.src]\nurl = \"https://example.org/x-{{version}}.tar.gz\"\nsha256 = \"{SHA}\"\n"
        )
    }

    #[test]
    fn substitutes_values_and_locations() {
        let recipes = load_all(&[(
            "x",
            &format!(
                "{HEADER}[vars]\npkg = \"example.org/x\"\nflags = [\"-a\", \"-b\"]\n\
                 [exports]\nall = [\"{{vars.flags}}\", \"-c\"]\n{}\
                 [[build]]\nrun = {{ cmd = [\"{{src}}/configure\", \"{{x.all}}\", \"--jobs={{jobs}}\", \"DESTDIR={{work:staged}}/usr {{vars.pkg}}\"], dir = \"{{src}}\" }}\n\
                 [[build]]\nmake = {{ dir = \"{{src}}/sub\", args = [\"V={{version}}/{{{{lit}}}}\"], \
                 install = {{ targets = [\"install\"] }} }}\n\
                 [[build]]\ninstall = {{ from = \"{{src}}/a\", to = \"{{dest}}/usr/bin/a\", mode = 0o755 }}\n\
                 [[build]]\nwrite = {{ to = \"{{out:conf}}\", contents = \"{{x.all}} {{version}}\", template = false }}\n",
                source()
            ),
        )])
        .unwrap();
        let plan = &recipes["x"].plan;

        let mut b = Build::default();
        let source = Source {
            url: "https://example.org/x-1.0.tar.gz".to_owned(),
            sha256: SHA.parse().unwrap(),
        };
        let src = b.unpack(&source, "src");
        let usr = b.work("staged").join("usr");
        b.cmd(src.join("configure"))
            .dir(&src)
            .args(["-a", "-b", "-c"])
            .arg(Arg::from("--jobs=").concat(Arg::jobs()))
            .arg(Arg::from("DESTDIR=").concat(usr).concat(" example.org/x"))
            .run();
        b.make(&src.join("sub")).arg("V=1.0/{lit}").run();
        let dest = b.root("/");
        b.make_install(&src.join("sub"), &dest, ["install"]);
        let to = b.root("/usr/bin/a");
        b.install(&src.join("a"), &to, Mode::EXECUTABLE);
        let conf = b.output("conf");
        b.write(&conf, "{x.all} {version}", Mode::FILE);
        let mut steps = b.into_steps();
        steps.push(super::super::Step::CheckEnv(dest));
        assert_eq!(plan.build, steps);
    }

    #[test]
    fn shares_values_and_sources_between_recipes() {
        let recipes = load_all(&[
            (
                "base",
                &format!(
                    "{HEADER}[exports]\nlibs = [[\"a\", \"liba.so\"], [\"b\", \"libb.so\"]]\ndir = \"usr/lib\"\n{}",
                    source()
                ),
            ),
            (
                "user",
                "version = \"{base.version}\"\nkind = \"library\"\nsummary = \"s\"\nlicense = \"MIT\"\n\
                 homepage = \"https://example.org\"\n[sources.src]\nfrom = \"base\"\n\
                 [[build]]\nsymlinks = { dir = \"{dest}/{base.dir}\", links = [\"{base.libs}\", [\"c\", \"c.so\"]] }\n",
            ),
        ])
        .unwrap();
        let user = &recipes["user"];
        assert_eq!(user.meta.version, "1.0");
        assert_eq!(
            user.plan.sources[0].url, "https://example.org/x-1.0.tar.gz",
            "base's source"
        );
        let links: Vec<String> = user.plan.build[1..4]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(links[0].contains("root:/usr/lib/a"), "{links:?}");
    }

    /// Steps default to the extracted `src` tree; `make.install` installs after building.
    #[test]
    fn defaults_to_the_source_tree() {
        let recipes = load_all(&[(
            "x",
            &format!(
                "{HEADER}cpe = \"gnu:x\"\n{}[[build]]\nrun.cmd = [\"./bootstrap\"]\n\
                 [[build]]\nmake = {{ args = [\"V=1\"], \
                 install = {{ targets = [\"install-strip\"] }} }}\n",
                source()
            ),
        )])
        .unwrap();
        let x = &recipes["x"];
        assert_eq!(
            x.meta.cpe.as_deref(),
            Some("cpe:2.3:a:gnu:x:1.0:*:*:*:*:*:*:*")
        );
        let steps: Vec<String> = x.plan.build.iter().map(ToString::to_string).collect();
        assert_eq!(
            steps[..4],
            [
                format!("unpack   sources:{SHA} → work:src"),
                "run      ./bootstrap  (in work:src)".to_owned(),
                "run      make -j{jobs} V=1  (in work:src)".to_owned(),
                "run      make install-strip DESTDIR=root:/  (in work:src)".to_owned(),
            ]
        );
    }

    /// A target's override merges over the recipe: tables key by key, arrays replace; its values
    /// are its own.
    #[test]
    fn merges_an_override() {
        let recipes = load_all(&[
            (
                "base",
                &format!(
                    "{HEADER}[vars]\nprefix = \"/usr\"\nv = \"base-{{vars.prefix}}\"\n\
                     [exports]\nflags = [\"-a\"]\nown = \"{{vars.v}}\"\n{}\
                     [[build]]\nrun = {{ cmd = [\"{{src}}/configure\", \"{{vars.v}}\"] }}\n",
                    source()
                ),
            ),
            (
                "t/base",
                "summary = \"static\"\n[vars]\nprefix = \"/cross\"\n\
                 [[build]]\nrun = { cmd = [\"{src}/configure\", \"{base.flags}\", \"{vars.v}\"] }\n",
            ),
            (
                "user",
                &format!("{HEADER}[[build]]\nrun = {{ cmd = [\"x\", \"{{base.own}}\", \"{{t/base.own}}\"] }}\n"),
            ),
        ])
        .unwrap();
        let merged = &recipes["t/base"];
        assert_eq!(merged.name().as_str(), "base");
        assert_eq!(
            (merged.meta.version.as_str(), merged.meta.summary.as_str()),
            ("1.0", "static")
        );
        assert_eq!(
            merged.plan.sources[0].url,
            "https://example.org/x-1.0.tar.gz"
        );
        let run = merged.plan.build[1].to_string();
        assert!(run.contains("configure -a base-/cross"), "{run}");
        assert!(
            recipes["base"].plan.build[1]
                .to_string()
                .contains("configure base-/usr")
        );
        let user = recipes["user"].plan.build[0].to_string();
        assert!(user.contains("x base-/usr base-/cross"), "{user}");
    }

    /// A target's own component, named by its name alone when no other target has one.
    #[test]
    fn names_a_targets_own_component() {
        let recipes = load_all(&[
            ("t/x", &format!("{HEADER}[exports]\ndir = \"usr/x\"\n{}", source())),
            (
                "y",
                "version = \"{x.version}\"\nkind = \"library\"\nsummary = \"s\"\nlicense = \"MIT\"\n\
                 homepage = \"https://example.org\"\n[sources.src]\nfrom = \"x\"\n\
                 [[build]]\nmkdir = \"{dest}/{x.dir}\"\n",
            ),
        ])
        .unwrap();
        let y = &recipes["y"];
        assert_eq!(y.meta.version, "1.0");
        assert_eq!(y.plan.sources[0].url, "https://example.org/x-1.0.tar.gz");
        assert!(
            y.plan
                .build
                .iter()
                .any(|step| step.to_string().contains("root:/usr/x"))
        );
        assert_eq!(recipes["t/x"].name().as_str(), "x");
    }

    #[test]
    fn rejects_invalid_recipes() {
        let src = source();
        for (recipes, why) in [
            (vec![("x", format!("{HEADER}color = 1\n"))], "unknown field"),
            (
                vec![("x", format!("{HEADER}[[build]]\nmkdir = \"{{src}}\"\n"))],
                "unbound location: no source",
            ),
            (
                vec![("x", format!("{HEADER}[[build]]\nmkdir = \"work:x\"\n"))],
                "not a location",
            ),
            (
                vec![(
                    "x",
                    format!("{HEADER}{src}[[build]]\nmkdir = \"{{src}}/../x\"\n"),
                )],
                "escaping path",
            ),
            (
                vec![("x", format!("{HEADER}[[build]]\nmkdir = \"{{version}}\"\n"))],
                "a value, not a location",
            ),
            (
                vec![(
                    "x",
                    format!(
                        "{HEADER}[[build]]\ninstall = {{ from = \"{{work:a}}\", to = \"{{root:/usr/a}}\" }}\n"
                    ),
                )],
                "unknown location",
            ),
            (
                vec![(
                    "x",
                    format!("{HEADER}[[build]]\nmkdir = \"{{toolchain.root}}\"\n"),
                )],
                "unknown value",
            ),
            (
                vec![(
                    "x",
                    format!(
                        "{HEADER}[sources.dest]\nurl = \"https://x/a.tar\"\nsha256 = \"{SHA}\"\n"
                    ),
                )],
                "a source named dest",
            ),
            (
                vec![(
                    "x",
                    format!(
                        "{HEADER}[[build]]\ninstall = {{ from = \"{{work:a}}\", to = \"{{work:b}}\", mode = \"4755\" }}\n"
                    ),
                )],
                "setuid",
            ),
            (
                vec![("x", format!("{HEADER}[[build]]\nshell = \"rm -rf /\"\n"))],
                "unknown step kind",
            ),
            (
                vec![(
                    "x",
                    format!(
                        "{HEADER}[[build]]\nwrite.to = \"{{work:a}}\"\nwrite.contents = \"a\"\n\
                         write.file = \"a\"\n"
                    ),
                )],
                "write of contents and a file",
            ),
            (
                vec![(
                    "x",
                    format!("{HEADER}{src}[[build]]\nmake.dest = \"{{work:a}}\"\n"),
                )],
                "make destination without install",
            ),
            (
                vec![(
                    "x",
                    format!(
                        "{HEADER}{src}[[build]]\ngo-build.commands = [[\"./x\", \"/usr/bin/x\"]]\n\
                         go-build.libraries = \"{{work:a}}\"\n"
                    ),
                )],
                "libraries without cgo",
            ),
            (
                vec![(
                    "x",
                    format!("{HEADER}{src}[[build]]\npatch.files = [\"../etc/passwd\"]\n"),
                )],
                "patch outside the recipe",
            ),
            (
                vec![(
                    "x",
                    format!("{HEADER}[vars]\na = \"{{vars.b}}\"\nb = \"{{vars.a}}\"\n"),
                )],
                "cycle",
            ),
            (
                vec![(
                    "x",
                    format!("{HEADER}[vars]\nl = [\"a\"]\nt = \"x {{vars.l}}\"\n"),
                )],
                "list in a string",
            ),
            (
                vec![
                    ("x", format!("{HEADER}[exports]\nv = \"{{y.vars.a}}\"\n")),
                    ("y", format!("{HEADER}[vars]\na = \"1\"\n")),
                ],
                "private vars",
            ),
            (
                vec![
                    (
                        "x",
                        format!("{HEADER}[[build]]\nrun = {{ cmd = [\"{{dep:t/y/missing}}\"] }}\n"),
                    ),
                    ("y", HEADER.to_owned()),
                ],
                "output nobody writes",
            ),
            (vec![("vars", HEADER.to_owned())], "reserved name"),
            (
                vec![("x", format!("{HEADER}[sources.src]\nfrom = \"nope\"\n"))],
                "unknown source recipe",
            ),
            (
                vec![
                    ("t/x", HEADER.to_owned()),
                    ("u/x", HEADER.to_owned()),
                    ("y", format!("{HEADER}[vars]\nv = \"{{x.version}}\"\n")),
                ],
                "a name two targets' own components have",
            ),
            (
                vec![("x", HEADER.to_owned()), ("t/x", "color = 1\n".to_owned())],
                "unknown field in an override",
            ),
        ] {
            let recipes: Vec<(&str, &str)> =
                recipes.iter().map(|(n, t)| (*n, t.as_str())).collect();
            let result = load_all(&recipes).and_then(|all| {
                // What the pipeline checks: the outputs used exist.
                for recipe in all.values() {
                    for (dep, output) in &recipe.plan.uses {
                        let producer = all.get(dep.component.as_str()).context("unknown")?;
                        if let Some(output) = output {
                            ensure!(producer.plan.outputs.contains(output), "missing output");
                        }
                    }
                }
                Ok(all)
            });
            assert!(result.is_err(), "{why}");
        }
    }
}
