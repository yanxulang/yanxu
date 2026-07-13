use crate::lexer;
use crate::token::TokenKind;

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
}
