use serde::{Deserialize, Serialize};
use std::fmt;
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    pub name: String,
    pub text: String,
}

impl SourceFile {
    pub fn new(name: impl Into<String>, text: impl Into<String>) -> Rc<Self> {
        Rc::new(Self {
            name: name.into(),
            text: text.into(),
        })
    }

    pub fn line(&self, number: usize) -> Option<&str> {
        self.text.lines().nth(number.saturating_sub(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub source: Rc<SourceFile>,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl Span {
    pub fn synthetic() -> Self {
        Self::new(SourceFile::new("<内部>", ""), 1, 1, 1, 1)
    }

    pub fn new(
        source: Rc<SourceFile>,
        line: usize,
        column: usize,
        end_line: usize,
        end_column: usize,
    ) -> Self {
        Self {
            source,
            line,
            column,
            end_line,
            end_column,
        }
    }

    pub fn through(&self, end: &Span) -> Self {
        Self::new(
            self.source.clone(),
            self.line,
            self.column,
            end.end_line,
            end.end_column,
        )
    }

    pub fn render(&self, label: &str, message: &str) -> String {
        let source_line = self.source.line(self.line).unwrap_or("");
        let number_width = self.line.to_string().len();
        let characters: Vec<char> = source_line.chars().collect();
        let caret_offset: usize = characters
            .iter()
            .take(self.column.saturating_sub(1))
            .map(|character| character_width(*character))
            .sum();
        let caret_width = if self.line == self.end_line {
            characters
                .iter()
                .skip(self.column.saturating_sub(1))
                .take(self.end_column.saturating_sub(self.column))
                .map(|character| character_width(*character))
                .sum::<usize>()
                .max(1)
        } else {
            characters
                .iter()
                .skip(self.column.saturating_sub(1))
                .map(|character| character_width(*character))
                .sum::<usize>()
                .max(1)
        };
        format!(
            "{label}：{message}\n  --> {}:{}:{}\n{:width$} |\n{} | {}\n{:width$} | {}{}",
            self.source.name,
            self.line,
            self.column,
            "",
            self.line,
            source_line,
            "",
            " ".repeat(caret_offset),
            "^".repeat(caret_width),
            width = number_width,
        )
    }
}

fn character_width(character: char) -> usize {
    match character {
        '\t' => 4,
        character if character.is_ascii() => 1,
        _ => 2,
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.source.name, self.line, self.column)
    }
}
