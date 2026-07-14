use crate::lexer;
use crate::token::TokenKind;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{CompletionType, Config, Context, Editor, Helper};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// 判断一段 REPL 输入是否还需要后续行。
///
/// 块结构、括号、未闭合字符串和缺少语句终止符都会触发续行。
pub fn needs_more_input(source: &str) -> bool {
    let tokens = match lexer::scan(source) {
        Ok(tokens) => tokens,
        Err(error) => return error.message == "字符串未闭合",
    };

    let mut blocks = 0_i32;
    let mut delimiters = 0_i32;
    let mut previous_was_colon = false;
    let mut last = None;
    for token in &tokens {
        match &token.kind {
            TokenKind::LeftParen | TokenKind::LeftBracket | TokenKind::LeftBrace => delimiters += 1,
            TokenKind::RightParen | TokenKind::RightBracket | TokenKind::RightBrace => {
                delimiters -= 1;
            }
            TokenKind::If | TokenKind::While | TokenKind::For | TokenKind::Try => blocks += 1,
            TokenKind::Function | TokenKind::Class if !previous_was_colon => blocks += 1,
            TokenKind::End => blocks -= 1,
            TokenKind::Eof => break,
            _ => {}
        }
        previous_was_colon = matches!(token.kind, TokenKind::Colon);
        last = Some(&token.kind);
    }

    if blocks > 0 || delimiters > 0 {
        return true;
    }
    !matches!(last, None | Some(TokenKind::Semicolon | TokenKind::End))
}

pub fn history_path() -> PathBuf {
    std::env::var_os("YANXU_HISTORY")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".yanxu_history")))
        .unwrap_or_else(|| PathBuf::from(".yanxu_history"))
}

pub fn load_history() -> Vec<String> {
    fs::read_to_string(history_path())
        .unwrap_or_default()
        .lines()
        .filter(|line| *line != "#V2")
        .map(|line| line.replace("\\n", "\n"))
        .collect()
}

pub fn append_history(entry: &str) {
    let entry = entry.trim();
    if entry.is_empty() {
        return;
    }
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_path())
    {
        let _ = writeln!(file, "{}", entry.replace('\n', "\\n"));
    }
}

pub fn completions(prefix: &str, history: &[String]) -> Vec<String> {
    const KEYWORDS: &[&str] = &[
        "令",
        "定",
        "置",
        "言",
        "若",
        "则",
        "否则",
        "终",
        "当",
        "逐",
        "于",
        "异",
        "候",
        "法",
        "类",
        "协",
        "纳",
        "域",
        "公",
        "私",
        "只",
        "静",
        "引",
        "为",
        "归",
        "试",
        "救",
        "抛",
        "真",
        "假",
        "空",
        "长度",
        "类型",
        "范围",
        "映射",
        "筛选",
        "折叠",
        "排序",
        "反转",
        "包含",
        "寻找",
        "取消",
        "任务状态",
        "并候",
    ];
    let mut values = KEYWORDS.iter().map(ToString::to_string).collect::<Vec<_>>();
    for entry in history {
        if let Ok(tokens) = lexer::scan(entry) {
            values.extend(tokens.into_iter().filter_map(|token| match token.kind {
                TokenKind::Identifier(name) => Some(name),
                _ => None,
            }));
        }
    }
    values.retain(|candidate| candidate.starts_with(prefix));
    values.sort();
    values.dedup();
    values
}

pub struct ReplHelper {
    observed: Vec<String>,
}

impl ReplHelper {
    pub fn new(history: &[String]) -> Self {
        Self {
            observed: history.to_vec(),
        }
    }

    pub fn observe(&mut self, source: &str) {
        if !source.trim().is_empty() {
            self.observed.push(source.into());
        }
    }

    fn candidates(&self, prefix: &str) -> Vec<Pair> {
        completions(prefix, &self.observed)
            .into_iter()
            .map(|candidate| Pair {
                display: candidate.clone(),
                replacement: candidate,
            })
            .collect()
    }
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        position: usize,
        _context: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let start = line[..position]
            .char_indices()
            .rev()
            .find(|(_, character)| completion_separator(*character))
            .map_or(0, |(index, character)| index + character.len_utf8());
        Ok((start, self.candidates(&line[start..position])))
    }
}

impl Hinter for ReplHelper {
    type Hint = String;
}

impl Highlighter for ReplHelper {}

impl Validator for ReplHelper {
    fn validate(&self, context: &mut ValidationContext<'_>) -> rustyline::Result<ValidationResult> {
        let input = context.input();
        if input.trim_start().starts_with(':') || !needs_more_input(input) {
            Ok(ValidationResult::Valid(None))
        } else {
            Ok(ValidationResult::Incomplete)
        }
    }
}

impl Helper for ReplHelper {}

pub type LineEditor = Editor<ReplHelper, DefaultHistory>;

pub fn line_editor(history: &[String]) -> rustyline::Result<LineEditor> {
    let config = Config::builder()
        .completion_type(CompletionType::List)
        .auto_add_history(false)
        .build();
    let mut editor = Editor::with_config(config)?;
    editor.set_helper(Some(ReplHelper::new(history)));
    for entry in history {
        let _ = editor.add_history_entry(entry);
    }
    Ok(editor)
}

fn completion_separator(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '（' | '）'
                | '('
                | ')'
                | '【'
                | '】'
                | '['
                | ']'
                | '{'
                | '}'
                | '，'
                | ','
                | '；'
                | ';'
                | '：'
                | ':'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_multiline_blocks() {
        assert!(needs_more_input("若 真 则\n言「是」；\n"));
        assert!(!needs_more_input("若 真 则\n言「是」；\n终\n"));
    }

    #[test]
    fn type_names_do_not_open_blocks() {
        assert!(!needs_more_input("令 回调：法 为 空；"));
    }

    #[test]
    fn completes_keywords_and_history_words() {
        let items = completions("法", &["法 求和（）".into()]);
        assert!(items.contains(&"法".into()));
    }

    #[test]
    fn terminal_helper_offers_tab_candidates_from_session() {
        let mut helper = ReplHelper::new(&[]);
        helper.observe("法 求和（甲：数，乙：数）：数 则 归 甲 加 乙；终");
        let candidates = helper.candidates("求");
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.replacement == "求和")
        );
    }
}
