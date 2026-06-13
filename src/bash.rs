use anyhow::{Context, Result};
use tree_sitter::{Node, Parser, Point};

use crate::{
    input::{FileKind, SourceFile},
    model::{Location, safe_snippet},
};

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
}

pub fn analyze(file: &SourceFile) -> Result<BashAnalysis> {
    if !file.kind.is_script() {
        return Ok(BashAnalysis::default());
    }

    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .context("cannot initialize Bash parser")?;
    let tree = parser
        .parse(&file.text, None)
        .context("Bash parser returned no syntax tree")?;

    let default_phase = match file.kind {
        FileKind::Install => Some("install-scriptlet".to_owned()),
        _ => None,
    };
    let mut output = BashAnalysis::default();
    walk(
        tree.root_node(),
        file.text.as_bytes(),
        default_phase.as_deref(),
        &mut output,
    );
    Ok(output)
}

fn walk(node: Node<'_>, source: &[u8], phase: Option<&str>, output: &mut BashAnalysis) {
    let current_phase = if node.kind() == "function_definition" {
        function_name(node, source).or_else(|| phase.map(ToOwned::to_owned))
    } else {
        phase.map(ToOwned::to_owned)
    };

    if node.is_error() || node.is_missing() {
        output.parse_errors.push(location(node, source));
    }

    if node.kind() == "command" {
        output.commands.push(Command {
            text: node_text(node, source),
            command_name: command_name(node, source),
            location: location(node, source),
            phase: current_phase.clone(),
            node_kind: node.kind().to_owned(),
        });
    } else if node.kind() == "pipeline" {
        output.pipelines.push(Command {
            text: node_text(node, source),
            command_name: None,
            location: location(node, source),
            phase: current_phase.clone(),
            node_kind: node.kind().to_owned(),
        });
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, current_phase.as_deref(), output);
    }
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

fn location(node: Node<'_>, source: &[u8]) -> Location {
    let Point { row, column } = node.start_position();
    Location {
        line: row + 1,
        column: column + 1,
        snippet: safe_snippet(&node_text(node, source)),
    }
}
