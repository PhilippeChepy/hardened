//! Recipes: a target's components in `specs/targets/<target>/components/<name>.toml`, and those
//! several targets build in `specs/components/<name>.toml`, which a target's file of the same name
//! overrides: merged over it, tables key by key, any other value (an array of steps included)
//! replacing the recipe's. A recipe using files (patches, configuration) is a directory,
//! `<name>/spec.toml` next to its files; overrides use their recipe's. `{<component>.<key>}`
//! names a target's own component by its name alone when no other target has one.
//!
//! A recipe is data: its metadata, sources, and its build as a list of steps of a fixed set of
//! kinds, each a call of the [`Build`] API (or of a policy helper, such as
//! [`Build::go_build`]). The result is a [`super::Plan`]. `version = "workspace"` is the OS
//! version (for the components built from this repository).
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
//! A step's `dir`, `src` or `tree` left out is the extracted `src` source (a command without one
//! runs in `work:` when `src` is no archive). `cpe = "<vendor>:<product>"` is an application's CPE
//! 2.3 name at `version`.
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
//! make.install = ["install", "PREFIX=/usr"]
//! ```

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail, ensure};
use serde::Deserialize;
use toml::Value;

use super::{
    Arg, Base, Build, CargoBinary, Cgo, ComponentName, ComponentType, Configure, ContainerImage, GoBuild, Loc, Meta,
    Mode, Output, Source, Unit, WORKSPACE_VERSION,
};

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
    local: Vec<String>,
    /// The components of its target it builds with (its environment's are always there).
    #[serde(default)]
    depends_on: Vec<String>,
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
#[serde(deny_unknown_fields)]
struct SourceFile {
    url: Option<String>,
    sha256: Option<String>,
    /// A shared recipe's source: `<component>` (its `src`) or `<component>/<source>`.
    from: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageFile {
    /// Absolute path in the image.
    entrypoint: String,
    /// `[uid, gid]`.
    user: (u32, u32),
}

/// One or several.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Many<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> Many<T> {
    fn items(&self) -> &[T] {
        match self {
            Self::One(item) => std::slice::from_ref(item),
            Self::Many(items) => items,
        }
    }
}

/// A step: one [`Build`] call, or one per item of a list. A `dir`, `src` or `tree` left out is the
/// extracted `src` source (commands without one run in `work:` when there is none).
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
        dir: Option<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        into: String,
    },
    /// `make -j{jobs}` in `dir`, with `args`; then, with `install`, `make <install>
    /// DESTDIR=<dest>` (`install = true` is `install = ["install"]`).
    Make {
        dir: Option<String>,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        install: Option<Targets>,
        dest: Option<String>,
    },
    /// `configure --prefix=<prefix> <args>` (`/usr` by default), `make` and `make install` into
    /// `dest`.
    #[serde(rename_all = "kebab-case")]
    Configure {
        src: Option<String>,
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
    /// A CMake project, installed into `dest`.
    Cmake {
        src: Option<String>,
        dest: Option<String>,
        #[serde(default)]
        args: Vec<String>,
    },
    /// A Meson project, installed into `dest`.
    Meson {
        src: Option<String>,
        dest: Option<String>,
        #[serde(default)]
        args: Vec<String>,
    },
    /// Go commands (`[package, install path]`), built with the hardened defaults: pure Go, or
    /// with `cgo = true` linked statically against musl and, in `libraries`, other libraries'
    /// installed `/usr` tree.
    GoBuild {
        tree: Option<String>,
        commands: Vec<(String, String)>,
        #[serde(default)]
        cgo: bool,
        libraries: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        /// Link-time `-X` variables, `[name, value]`.
        #[serde(default)]
        vars: Vec<(String, String)>,
    },
    /// Builds workspace binaries (`[package, install path]`), offline and locked (the crates are
    /// fetched before, with network access), then strips them.
    CargoBuild {
        binaries: Vec<(String, String)>,
    },
    /// Configures the kernel tree with `fragment` (a file of the recipe's directory), checking
    /// that every option made it into `.config`.
    KernelConfig {
        tree: Option<String>,
        #[serde(default)]
        args: Vec<String>,
        fragment: String,
    },
    Mkdir(Many<String>),
    /// Installs one file, with `mode` (`0o644` by default).
    Install {
        from: String,
        to: String,
        mode: Option<u32>,
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
    Remove(Many<String>),
    /// Writes `contents`, or a `file` of the recipe's directory, as is or, as a `template`, with
    /// its values substituted.
    Write {
        to: String,
        contents: Option<String>,
        file: Option<String>,
        mode: Option<u32>,
        #[serde(default)]
        template: bool,
    },
    /// Applies patches, files of the recipe's directory, in order.
    Patch {
        tree: Option<String>,
        files: Vec<String>,
    },
}

/// The targets of `make.install`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Targets {
    /// `true`: `install`.
    Default(bool),
    Named(Vec<String>),
}

/// The values of every recipe, resolved: `<recipe>.<key>` (`version`, `vars.<key>`,
/// `<export>`), where `<recipe>` is its id (`<component>`, or
/// `<target>/<component>` for a target's own). Their strings are templates holding no value: only locations,
/// `{jobs}`, `{epoch}` and escaped braces.
type Values = BTreeMap<String, Value>;

/// A component's recipe, loaded. Recipes load once per process: the strings the plan and the
/// metadata hold as `'static` are leaked.
pub struct Declarative {
    /// Its id in the values.
    id: String,
    pub(super) meta: Meta,
    pub(super) depends_on: Vec<String>,
    pub(super) local: Vec<super::RepoPath>,
    sources: BTreeMap<String, Source>,
    images: BTreeMap<String, ContainerImage>,
    values: Arc<Values>,
    /// The files of the recipe's directory its steps use, by path.
    files: BTreeMap<String, String>,
    steps: Vec<StepFile>,
}

/// Every recipe of `specs/` (see the module documentation): the components, with the target
/// that overrides each, if any.
pub fn load(specs: &Path) -> anyhow::Result<Vec<(Option<ComponentName>, Declarative)>> {
    let tables = read(&specs.join("components"))?;
    let mut raws = BTreeMap::new();
    for (name, (entry, table)) in &tables {
        let id = name.to_string();
        raws.insert(id.clone(), Raw::new(id, name, None, entry, table.clone())?);
    }
    for (target, entry) in crate::specs::entries(&specs.join("targets"))? {
        let Some(overrides) = entry.dir.map(|dir| dir.join("components")).filter(|dir| dir.is_dir()) else {
            continue;
        };
        for (name, (own_entry, own)) in read(&overrides)? {
            let id = format!("{target}/{name}");
            let raw = match tables.get(&name) {
                // An override of a shared recipe.
                Some((entry, base)) => {
                    ensure!(
                        own_entry.dir.is_none(),
                        "{}: an override has no directory: its files are its component's",
                        own_entry.spec.display()
                    );
                    let mut table = base.clone();
                    merge(&mut table, own);
                    let mut raw = Raw::new(id.clone(), &name, Some(&target), entry, table)?;
                    raw.path = own_entry.spec;
                    raw
                }
                // The target's own component.
                None => Raw::new(id.clone(), &name, Some(&target), &own_entry, own)?,
            };
            raws.insert(id, raw);
        }
    }
    // A target's own component is also named by its name alone, unless that is ambiguous.
    let mut aliases: BTreeMap<String, Option<String>> = BTreeMap::new();
    for raw in raws
        .values()
        .filter(|raw| raw.target.is_some() && !tables.contains_key(&raw.name))
    {
        let alias = aliases
            .entry(raw.name.to_string())
            .or_insert_with(|| Some(raw.id.clone()));
        if alias.as_ref() != Some(&raw.id) {
            *alias = None;
        }
    }
    let aliases: BTreeMap<String, String> = (aliases.into_iter())
        .filter_map(|(name, id)| Some((name, id?)))
        .collect();
    let values = Arc::new(resolve_all(&raws, &aliases)?);
    let raws = Loaded { raws, aliases };
    (raws.raws.values())
        .map(|raw| {
            let recipe = Declarative::new(raw, &raws, &values).with_context(|| raw.path.display().to_string())?;
            Ok((raw.target.clone(), recipe))
        })
        .collect()
}

/// The recipes being loaded, by id, and the target-only ones by name too.
struct Loaded {
    raws: BTreeMap<String, Raw>,
    /// `<component>` → `<target>/<component>`, for a component only one target has.
    aliases: BTreeMap<String, String>,
}

impl Loaded {
    /// The recipe `name` (an id, or a target-only component's name).
    fn get(&self, name: &str) -> Option<&Raw> {
        (self.raws.get(name)).or_else(|| self.aliases.get(name).and_then(|id| self.raws.get(id)))
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
        let table: toml::Table = toml::from_str(&text).with_context(|| path.display().to_string())?;
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

struct Raw {
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

impl Raw {
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
fn resolve_all(raws: &BTreeMap<String, Raw>, aliases: &BTreeMap<String, String>) -> anyhow::Result<Values> {
    let resolver = Resolver {
        raws,
        aliases,
        values: RefCell::new(BTreeMap::new()),
        resolving: RefCell::new(Vec::new()),
    };
    for (name, raw) in raws {
        resolver.get(&format!("{name}.version"))?;
        for key in raw.file.vars.keys() {
            resolver.get(&format!("{name}.vars.{key}"))?;
        }
        for key in raw.file.exports.keys() {
            ensure!(
                !matches!(key.as_str(), "version" | "vars") && !key.contains('.'),
                "{name}: invalid export name {key:?}"
            );
            resolver.get(&format!("{name}.{key}"))?;
        }
    }
    // A target-only component's values by its name alone too.
    let mut values = resolver.values.into_inner();
    for (alias, id) in aliases {
        let prefix = format!("{id}.");
        let named: Vec<(String, Value)> = (values.iter())
            .filter_map(|(key, value)| Some((format!("{alias}.{}", key.strip_prefix(&prefix)?), value.clone())))
            .collect();
        values.extend(named);
    }
    Ok(values)
}

struct Resolver<'a> {
    raws: &'a BTreeMap<String, Raw>,
    aliases: &'a BTreeMap<String, String>,
    values: RefCell<Values>,
    /// The values being resolved, to report cycles.
    resolving: RefCell<Vec<String>>,
}

impl Resolver<'_> {
    /// The value `<component>.<key>`.
    fn get(&self, full: &str) -> anyhow::Result<Value> {
        if let Some(value) = self.values.borrow().get(full) {
            return Ok(value.clone());
        }
        ensure!(
            !self.resolving.borrow().iter().any(|key| key == full),
            "{{{full}}} depends on itself: {}",
            self.resolving.borrow().join(" → ")
        );
        self.resolving.borrow_mut().push(full.to_owned());
        let value = self.compute(full).with_context(|| format!("{{{full}}}"));
        self.resolving.borrow_mut().pop();
        let value = value?;
        self.values.borrow_mut().insert(full.to_owned(), value.clone());
        Ok(value)
    }

    fn compute(&self, full: &str) -> anyhow::Result<Value> {
        let (component, key) = full.split_once('.').context("no key")?;
        let raw = (self.raws.get(component))
            .or_else(|| self.aliases.get(component).and_then(|id| self.raws.get(id)))
            .with_context(|| format!("unknown recipe {component}"))?;
        let file = &raw.file;
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
            None => (file.exports.get(key)).with_context(|| format!("{component} exports no {key}"))?,
        };
        self.value(component, raw_value)
    }

    /// `value` (of `component`'s recipe) with its strings substituted and its lists spliced.
    fn value(&self, component: &str, value: &Value) -> anyhow::Result<Value> {
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
            Value::Integer(_) | Value::Boolean(_) => value.clone(),
            _ => bail!("only strings and lists of them are values"),
        })
    }

    /// The items `item` stands for, if it is exactly the reference of a list.
    fn splice(&self, component: &str, item: &Value) -> anyhow::Result<Option<Vec<Value>>> {
        let Some(key) = list_reference(item) else {
            return Ok(None);
        };
        match self.lookup(component, key)? {
            Some(Value::Array(list)) => Ok(Some(list)),
            _ => Ok(None),
        }
    }

    fn text(&self, component: &str, text: &str) -> anyhow::Result<String> {
        let lookup = |key: &str| self.lookup(component, key);
        Ok(template(tokens(text, &lookup)?))
    }

    /// A value seen from `component`'s recipe, if `key` names one.
    fn lookup(&self, component: &str, key: &str) -> anyhow::Result<Option<Value>> {
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
fn tokens(text: &str, lookup: &dyn Fn(&str) -> anyhow::Result<Option<Value>>) -> anyhow::Result<Vec<Token>> {
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
        let end = after.find('}').with_context(|| format!("unclosed '{{' in {text:?}"))?;
        let key = &after[..end];
        ensure!(!key.is_empty() && !key.contains('{'), "invalid '{{{key}}}' in {text:?}");
        rest = &after[end + 1..];
        let token = match key {
            "jobs" => Token::Jobs,
            "epoch" => Token::Epoch,
            _ => match lookup(key)? {
                Some(Value::String(value)) => {
                    // A resolved value: a template holding no value.
                    for token in tokens(&value, &|_| Ok(None))? {
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
                Some(Value::Array(_)) => {
                    bail!("{{{key}}} is a list: a list is used as a whole item of a list, not in {text:?}")
                }
                Some(value) => {
                    literal.push_str(&value.to_string());
                    continue;
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
    plain(template, tokens(template, &|_| Ok(None))?)
}

/// The text of `tokens`, which must hold no location, `{jobs}` or `{epoch}`.
fn plain(text: &str, tokens: Vec<Token>) -> anyhow::Result<String> {
    let mut out = String::new();
    for token in tokens {
        match token {
            Token::Text(t) => out.push_str(&t),
            Token::Location(key) => bail!("unknown value {{{key}}} in {text:?}"),
            Token::Jobs | Token::Epoch => bail!("{text:?}: {{jobs}} and {{epoch}} are for commands"),
        }
    }
    Ok(out)
}

/// `path` if relative, without empty, `.` or `..` segments.
fn checked(path: &str) -> anyhow::Result<&str> {
    ensure!(
        !path.is_empty() && path.split('/').all(|segment| !matches!(segment, "" | "." | "..")),
        "{path:?} is not a relative path without '.' or '..'"
    );
    Ok(path)
}

fn leak(text: &str) -> &'static str {
    Box::leak(text.to_owned().into_boxed_str())
}

fn output(component: ComponentName, name: &str) -> anyhow::Result<Output> {
    ensure!(
        Output::is_valid(name),
        "output names are file names: alphanumerics and '._-' ({name:?})"
    );
    Ok(Output::new(component, leak(name)))
}

/// The CPE 2.3 name `cpe` stands for: `<vendor>:<product>` of an application at `version`, or a
/// whole `cpe:2.3:...` name.
fn cpe_of(cpe: &str, version: &str) -> anyhow::Result<String> {
    if cpe.starts_with("cpe:") {
        return Ok(cpe.to_owned());
    }
    let (vendor, product) = (cpe.split_once(':'))
        .filter(|(vendor, product)| !vendor.is_empty() && !product.is_empty() && !product.contains(':'))
        .with_context(|| format!("cpe {cpe:?}: `<vendor>:<product>`, or a whole `cpe:2.3:` name"))?;
    Ok(format!("cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"))
}

fn mode(mode: Option<u32>) -> anyhow::Result<Mode> {
    let Some(bits) = mode else {
        return Ok(Mode::FILE);
    };
    ensure!(bits <= 0o777, "mode {bits:#o}: only permission bits");
    Ok(Mode::new(bits))
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

impl Declarative {
    fn new(raw: &Raw, raws: &Loaded, values: &Arc<Values>) -> anyhow::Result<Self> {
        let name = raw.id.as_str();
        let file = &raw.file;
        let lookup = |key: &str| lookup(values, name, key);
        let text = |text: &str| plain(text, tokens(text, &lookup)?);

        let mut sources = BTreeMap::new();
        for (key, source) in &file.sources {
            ensure!(key != "dest", "sources.dest: `{{dest}}` is the component's tree");
            checked(key).with_context(|| format!("sources.{key}: a source name is a directory name"))?;
            let resolved = match source {
                SourceFile {
                    from: Some(from),
                    url: None,
                    sha256: None,
                } => {
                    let (component, other_key) = from.split_once('/').unwrap_or((from, "src"));
                    let other = (raws.get(component)).with_context(|| format!("sources.{key}: unknown {component}"))?;
                    Declarative::source_of(other, other_key, values)?
                }
                SourceFile {
                    from: None,
                    url: Some(_),
                    sha256: Some(_),
                    ..
                } => Declarative::source_of(raw, key, values)?,
                _ => bail!("sources.{key}: either url and sha256, or from"),
            };
            sources.insert(key.clone(), resolved);
        }

        let mut images = BTreeMap::new();
        for (image, spec) in &file.images {
            let image_name: ComponentName = image.parse().with_context(|| format!("images.{image}"))?;
            ensure!(
                spec.entrypoint.starts_with('/'),
                "images.{image}: the entrypoint is absolute"
            );
            images.insert(
                image.clone(),
                ContainerImage {
                    name: image_name,
                    entrypoint: leak(&spec.entrypoint),
                    user: spec.user,
                },
            );
        }

        let steps = |list: &[Value], phase: &str| -> anyhow::Result<Vec<StepFile>> {
            let mut out = Vec::new();
            for (i, step) in list.iter().enumerate() {
                let step: StepFile = splice(values, name, step)?
                    .try_into()
                    .with_context(|| format!("{phase} step {}", i + 1))?;
                out.push(step);
            }
            Ok(out)
        };
        let build = steps(&file.build, "build")?;

        let mut files = BTreeMap::new();
        for step in &build {
            let names: Vec<&String> = match step {
                StepFile::Patch { files, .. } => files.iter().collect(),
                StepFile::Write { file: Some(file), .. } => vec![file],
                StepFile::KernelConfig { fragment, .. } => vec![fragment],
                _ => Vec::new(),
            };
            for path in names {
                ensure!(
                    super::RepoPath::try_from(path.as_str()).is_ok(),
                    "{path:?} is not a relative path in the recipe's directory"
                );
                let contents = std::fs::read_to_string(raw.dir.join(path))
                    .with_context(|| raw.dir.join(path).display().to_string())?;
                files.insert(path.clone(), contents);
            }
        }

        let local = (file.local.iter())
            .map(|path| super::RepoPath::try_from(path.as_str()).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<_>>()?;

        let version = final_text(&values[&format!("{name}.version")]).context("version")?;
        let purl = match &file.purl {
            Some(purl) => text(purl).context("purl")?,
            None => format!("pkg:generic/{}@{version}", raw.name),
        };
        let cpe = file
            .cpe
            .as_deref()
            .map(|cpe| cpe_of(&text(cpe)?, &version))
            .transpose()?;
        let meta = Meta {
            name: raw.name.clone(),
            version,
            kind: file.kind,
            summary: file.summary.clone(),
            license: file.license.clone(),
            homepage: file.homepage.clone(),
            purl,
            cpe,
        };
        for name in &file.depends_on {
            (name.parse::<ComponentName>()).with_context(|| format!("depends-on: {name:?} is not a component name"))?;
        }
        Ok(Self {
            id: raw.id.clone(),
            meta,
            depends_on: file.depends_on.clone(),
            local,
            sources,
            images,
            values: values.clone(),
            files,
            steps: build,
        })
    }

    /// The source `key` of `raw`'s recipe.
    fn source_of(raw: &Raw, key: &str, values: &Values) -> anyhow::Result<Source> {
        let name = raw.id.as_str();
        let source = (raw.file.sources.get(key)).with_context(|| format!("{name} has no source {key}"))?;
        let (Some(url), Some(sha256)) = (&source.url, &source.sha256) else {
            bail!("sources.{key} of {name} is not a download");
        };
        let lookup = |k: &str| lookup(values, name, k);
        let url = leak(&plain(url, tokens(url, &lookup)?)?);
        let sha256 = sha256
            .parse()
            .map_err(|e| anyhow::anyhow!("sources.{key}.sha256: {e}"))?;
        Ok(Source { url, sha256 })
    }

    fn run(&self, b: &mut Build, steps: &[StepFile], phase: &str) -> anyhow::Result<()> {
        let mut scope = Scope {
            recipe: self,
            locations: BTreeMap::new(),
        };
        // The build starts with its sources: archives (`.tar.*`, `.tgz`) extracted, other files as
        // they are.
        if phase == "build" {
            for (name, source) in &self.sources {
                let loc = if source.is_archive() {
                    b.unpack(source, name)
                } else {
                    b.source(source)
                };
                scope.bind(name, loc);
            }
        }
        for (i, step) in steps.iter().enumerate() {
            scope
                .step(b, step)
                .with_context(|| format!("{phase} step {} ({step:?})", i + 1))?;
        }
        Ok(())
    }

    /// Steps run with network access before the build, for lockfile-verified downloads only.
    pub(super) fn fetch(&self, b: &mut Build) -> anyhow::Result<()> {
        if self
            .steps
            .iter()
            .any(|step| matches!(step, StepFile::CargoBuild { .. }))
        {
            b.cargo_fetch();
        }
        Ok(())
    }

    /// The build, run without network access.
    pub(super) fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        self.run(b, &self.steps, "build")
    }
}

/// The recipe and the locations bound so far.
struct Scope<'a> {
    recipe: &'a Declarative,
    locations: BTreeMap<String, Loc>,
}

impl Scope<'_> {
    fn tokens(&self, text: &str) -> anyhow::Result<Vec<Token>> {
        let recipe = self.recipe;
        tokens(text, &|key| lookup(&recipe.values, &recipe.id, key))
    }

    fn text(&self, text: &str) -> anyhow::Result<String> {
        plain(text, self.tokens(text)?)
    }

    fn texts(&self, texts: &[String]) -> anyhow::Result<Vec<String>> {
        texts.iter().map(|text| self.text(text)).collect()
    }

    fn bind(&mut self, name: &str, loc: Loc) {
        self.locations.insert(name.to_owned(), loc);
    }

    /// The location `{key}`, then `suffix` (`/<path>`) if not empty.
    fn location(&self, b: &mut Build, key: &str, suffix: &str) -> anyhow::Result<Loc> {
        let own = || self.recipe.meta.name.clone();
        let base = match key.split_once(':') {
            None if key == "dest" => b.root("/"),
            Some(("work", path)) => b.work(checked(path)?),
            Some(("out", name)) => b.output(&output(own(), name)?),
            Some(("dep", reference)) => {
                let mut parts = reference.splitn(3, '/');
                let (Some(target), Some(component)) = (parts.next(), parts.next()) else {
                    bail!("{{{key}}}: `dep:<target>/<component>` or `dep:<target>/<component>/<output>`");
                };
                let unit = Unit {
                    target: target.parse()?,
                    component: component.parse()?,
                };
                match parts.next() {
                    None => b.input(&unit, None),
                    Some(name) => {
                        let name = output(unit.component.clone(), name)?.name();
                        b.input(&unit, Some(name))
                    }
                }
            }
            Some(("secret", name)) => b.secret(leak(name)),
            Some(("image", name)) => {
                let image = (self.recipe.images.get(name)).with_context(|| format!("{{{key}}}: no such image"))?;
                b.container_image(image)
            }
            Some(_) => bail!("unknown location {{{key}}}"),
            None => {
                (self.locations.get(key).cloned()).with_context(|| format!("no location {{{key}}} is bound yet"))?
            }
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

    /// A tree a step works in: `tree`, or the extracted `src` source.
    fn tree(&self, b: &mut Build, tree: Option<&str>) -> anyhow::Result<Loc> {
        match tree {
            Some(tree) => self.loc(b, tree),
            None => self
                .source_tree()
                .context("no extracted `src` source: give the directory"),
        }
    }

    /// Where a build system installs: `dest`, or the component's tree.
    fn dest(&self, b: &mut Build, dest: Option<&str>) -> anyhow::Result<Loc> {
        self.loc(b, dest.unwrap_or("{dest}"))
    }

    /// A field holding one location.
    fn loc(&self, b: &mut Build, text: &str) -> anyhow::Result<Loc> {
        match self.tokens(text)?.as_slice() {
            [Token::Location(key)] => self.location(b, key, ""),
            [Token::Location(key), Token::Text(suffix)] if !suffix.contains(char::is_whitespace) => {
                self.location(b, key, suffix)
            }
            _ => bail!("{text:?} is not a location (`{{dest}}`, `{{src}}`, `{{work:path}}`..., then `/path`)"),
        }
    }

    /// A command argument: text, values, locations, `{jobs}` and `{epoch}`.
    fn arg(&self, b: &mut Build, text: &str) -> anyhow::Result<Arg> {
        let mut arg: Option<Arg> = None;
        let push = |arg: &mut Option<Arg>, next: Arg| {
            *arg = Some(match arg.take() {
                Some(arg) => arg.concat(next),
                None => next,
            });
        };
        let mut tokens = self.tokens(text)?.into_iter().peekable();
        while let Some(token) = tokens.next() {
            match token {
                Token::Text(text) => push(&mut arg, Arg::from(text)),
                Token::Jobs => push(&mut arg, Arg::jobs()),
                Token::Epoch => push(&mut arg, Arg::epoch()),
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
                    push(&mut arg, Arg::from(self.location(b, &key, &suffix)?));
                }
            }
        }
        Ok(arg.unwrap_or_else(|| Arg::from("")))
    }

    fn args(&self, b: &mut Build, texts: &[String]) -> anyhow::Result<Vec<Arg>> {
        texts.iter().map(|text| self.arg(b, text)).collect()
    }

    fn env<'e>(&self, b: &mut Build, env: &'e [(String, String)]) -> anyhow::Result<Vec<(&'e str, Arg)>> {
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

    fn step(&mut self, b: &mut Build, step: &StepFile) -> anyhow::Result<()> {
        let recipe = self.recipe;
        match step {
            StepFile::Run { cmd, dir, env } => self.command(b, cmd, dir.as_deref(), env)?.run(),
            StepFile::Capture { cmd, dir, env, into } => {
                let into = self.loc(b, into)?;
                self.command(b, cmd, dir.as_deref(), env)?.capture(&into);
            }
            StepFile::Make {
                dir,
                args,
                env,
                install,
                dest,
            } => {
                let dir = self.tree(b, dir.as_deref())?;
                let args = self.args(b, args)?;
                let env = self.env(b, env)?;
                let mut command = b.make(&dir).args(args);
                for (key, value) in env {
                    command = command.env(key, value);
                }
                command.run();
                let targets = match install {
                    None => return Ok(()),
                    Some(Targets::Default(true)) => Vec::new(),
                    Some(Targets::Default(false)) => bail!("make.install: true, or the install targets"),
                    Some(Targets::Named(targets)) => self.texts(targets)?,
                };
                let dest = self.dest(b, dest.as_deref())?;
                b.make_install(&dir, &dest, &strs(&targets));
            }
            StepFile::Configure {
                src,
                dest,
                prefix,
                args,
                in_tree,
                env,
            } => {
                let src = self.tree(b, src.as_deref())?;
                let prefix = prefix.as_deref().map(|prefix| self.text(prefix)).transpose()?;
                let dest = self.dest(b, dest.as_deref())?;
                let args = self.texts(args)?;
                let env: Vec<(String, String)> = env
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), self.text(value)?)))
                    .collect::<anyhow::Result<_>>()?;
                let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                b.configure_make(
                    &src,
                    &dest,
                    Configure {
                        prefix: prefix.as_deref().unwrap_or("/usr"),
                        args: &strs(&args),
                        in_tree: *in_tree,
                        env: &env,
                    },
                );
            }
            StepFile::Cmake { src, dest, args } => {
                let src = self.tree(b, src.as_deref())?;
                let dest = self.dest(b, dest.as_deref())?;
                let args = self.texts(args)?;
                b.cmake_build(&src, &dest, &strs(&args));
            }
            StepFile::Meson { src, dest, args } => {
                let src = self.tree(b, src.as_deref())?;
                let dest = self.dest(b, dest.as_deref())?;
                let args = self.texts(args)?;
                b.meson_build(&src, &dest, &strs(&args));
            }
            StepFile::GoBuild {
                tree,
                commands,
                cgo,
                libraries,
                tags,
                vars,
            } => {
                let tree = self.tree(b, tree.as_deref())?;
                let cgo = match (cgo, libraries) {
                    (false, None) => Cgo::Disabled,
                    (false, Some(_)) => bail!("libraries are for cgo"),
                    (true, libraries) => Cgo::Enabled {
                        libraries: libraries.as_deref().map(|l| self.loc(b, l)).transpose()?,
                    },
                };
                let tags = self.texts(tags)?;
                let vars: Vec<(String, String)> = vars
                    .iter()
                    .map(|(name, value)| Ok((self.text(name)?, self.text(value)?)))
                    .collect::<anyhow::Result<_>>()?;
                let vars: Vec<(&str, &str)> = vars.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                for (package, install) in commands {
                    let (package, install) = (self.text(package)?, self.text(install)?);
                    b.go_build(GoBuild {
                        tree: &tree,
                        package: &package,
                        install: &install,
                        cgo: cgo.clone(),
                        tags: &strs(&tags),
                        vars: &vars,
                    });
                }
            }
            StepFile::CargoBuild { binaries } => {
                let binaries: Vec<CargoBinary> = binaries
                    .iter()
                    .map(|(package, install)| {
                        Ok(CargoBinary {
                            package: leak(&self.text(package)?),
                            install: leak(&self.text(install)?),
                        })
                    })
                    .collect::<anyhow::Result<_>>()?;
                b.cargo_build(&binaries);
            }
            StepFile::KernelConfig { tree, args, fragment } => {
                let tree = self.tree(b, tree.as_deref())?;
                let args = self.texts(args)?;
                b.kernel_config(&tree, &strs(&args), &recipe.files[fragment]);
            }
            StepFile::Mkdir(dirs) => {
                for dir in dirs.items() {
                    let dir = self.loc(b, dir)?;
                    b.mkdir(&dir);
                }
            }
            StepFile::Install { from, to, mode: m } => {
                let (from, to) = (self.loc(b, from)?, self.loc(b, to)?);
                b.install(&from, &to, mode(*m)?);
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
                contents,
                file,
                mode: m,
                template,
            } => {
                let to = self.loc(b, to)?;
                let contents = match (contents, file) {
                    (Some(contents), None) => contents.clone(),
                    (None, Some(file)) => recipe.files[file].clone(),
                    _ => bail!("write: either contents or file"),
                };
                let contents = if *template { self.text(&contents)? } else { contents };
                b.write(&to, contents, mode(*m)?);
            }
            StepFile::Patch { tree, files } => {
                let tree = self.tree(b, tree.as_deref())?;
                for path in files {
                    b.patch(&tree, path, &recipe.files[path]);
                }
            }
        }
        Ok(())
    }
}

fn strs(strings: &[String]) -> Vec<&str> {
    strings.iter().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "version = \"1.0\"\nkind = \"library\"\nsummary = \"s\"\nlicense = \"MIT\"\n\
                          homepage = \"https://example.org\"\n";
    const SHA: &str = "eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3";

    /// Loads recipes from `(id, text)` pairs (`<name>`, or `<target>/<name>` for a target's
    /// override), in a temporary `specs/`, by id.
    fn load_all(recipes: &[(&str, &str)]) -> anyhow::Result<BTreeMap<String, super::super::Recipe>> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("components")).unwrap();
        std::fs::create_dir_all(dir.path().join("targets")).unwrap();
        for (id, text) in recipes {
            let path = match id.split_once('/') {
                Some((target, name)) => dir.path().join(format!("targets/{target}/components/{name}.toml")),
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
            .map(|(target, c)| {
                let recipe = super::super::Recipe::describe(&c)?;
                let id = match target {
                    Some(target) => format!("{target}/{}", recipe.name()),
                    None => recipe.name().to_string(),
                };
                Ok((id, recipe))
            })
            .collect()
    }

    fn source() -> String {
        format!("[sources.src]\nurl = \"https://example.org/x-{{version}}.tar.gz\"\nsha256 = \"{SHA}\"\n")
    }

    #[test]
    fn substitutes_values_and_locations() {
        let recipes = load_all(&[(
            "x",
            &format!(
                "{HEADER}[vars]\npkg = \"example.org/x\"\nflags = [\"-a\", \"-b\"]\n\
                 [exports]\nall = [\"{{vars.flags}}\", \"-c\"]\n{}\
                 [[build]]\nrun = {{ cmd = [\"{{src}}/configure\", \"{{x.all}}\", \"--jobs={{jobs}}\", \"DESTDIR={{work:staged}}/usr {{vars.pkg}}\"], dir = \"{{src}}\" }}\n\
                 [[build]]\nmake = {{ dir = \"{{src}}/sub\", args = [\"V={{version}}/{{{{lit}}}}\"], install = true }}\n\
                 [[build]]\ninstall = {{ from = \"{{src}}/a\", to = \"{{dest}}/usr/bin/a\", mode = 0o755 }}\n\
                 [[build]]\nwrite = {{ to = \"{{out:conf}}\", contents = \"{{x.all}} {{version}}\", template = false }}\n",
                source()
            ),
        )])
        .unwrap();
        let plan = &recipes["x"].plan;

        let mut b = Build::for_tests();
        let source = Source {
            url: "https://example.org/x-1.0.tar.gz",
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
        b.make_install(&src.join("sub"), &dest, &[]);
        let to = b.root("/usr/bin/a");
        b.install(&src.join("a"), &to, Mode::EXECUTABLE);
        let conf = b.output(&Output::new("x".parse().unwrap(), "conf"));
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
        let links: Vec<String> = user.plan.build[1..4].iter().map(ToString::to_string).collect();
        assert!(links[0].contains("root:/usr/lib/a"), "{links:?}");
    }

    /// Steps default to the extracted `src` tree; `make.install` installs after building.
    #[test]
    fn defaults_to_the_source_tree() {
        let recipes = load_all(&[(
            "x",
            &format!(
                "{HEADER}cpe = \"gnu:x\"\n{}[[build]]\nrun.cmd = [\"./bootstrap\"]\n\
                 [[build]]\nmake = {{ args = [\"V=1\"], install = [\"install-strip\"] }}\n",
                source()
            ),
        )])
        .unwrap();
        let x = &recipes["x"];
        assert_eq!(x.meta.cpe.as_deref(), Some("cpe:2.3:a:gnu:x:1.0:*:*:*:*:*:*:*"));
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
        assert_eq!(merged.plan.sources[0].url, "https://example.org/x-1.0.tar.gz");
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
        assert!(y.plan.build.iter().any(|step| step.to_string().contains("root:/usr/x")));
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
                vec![("x", format!("{HEADER}{src}[[build]]\nmkdir = \"{{src}}/../x\"\n"))],
                "escaping path",
            ),
            (
                vec![("x", format!("{HEADER}[[build]]\nmkdir = \"{{version}}\"\n"))],
                "a value, not a location",
            ),
            (
                vec![(
                    "x",
                    format!("{HEADER}[[build]]\ninstall = {{ from = \"{{work:a}}\", to = \"{{root:/usr/a}}\" }}\n"),
                )],
                "unknown location",
            ),
            (
                vec![("x", format!("{HEADER}[[build]]\nmkdir = \"{{toolchain.root}}\"\n"))],
                "unknown value",
            ),
            (
                vec![(
                    "x",
                    format!("{HEADER}[sources.dest]\nurl = \"https://x/a.tar\"\nsha256 = \"{SHA}\"\n"),
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
                    format!("{HEADER}[[build]]\npatch = {{ tree = \"{{work:x}}\", files = [\"../etc/passwd\"] }}\n"),
                )],
                "patch outside the recipe",
            ),
            (
                vec![("x", format!("{HEADER}[vars]\na = \"{{vars.b}}\"\nb = \"{{vars.a}}\"\n"))],
                "cycle",
            ),
            (
                vec![("x", format!("{HEADER}[vars]\nl = [\"a\"]\nt = \"x {{vars.l}}\"\n"))],
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
            let recipes: Vec<(&str, &str)> = recipes.iter().map(|(n, t)| (*n, t.as_str())).collect();
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
