use plex::lexer;

#[derive(Debug, Clone)]
pub enum Token {
    Ident(String),

    If,
    ElseIf,
    Else,
    Return,

    Bool(bool),
    Number(f64),
    String(String),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Equals,
    Assign,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Semi,

    Whitespace,
    Newline,
    Comment,
}

lexer! {
    fn next_token(text: 'a) -> (Token, &'a str);

    r#"[ \t\r]+"# => (Token::Whitespace, text),
    r#"\n"# => (Token::Newline, text),
    // Python-style comments (# ...)
    r#"#[^\n]*"# => (Token::Comment, text),

    r#"if"# => (Token::If, text),
    r#"elif"# => (Token::ElseIf, text),
    r#"else"# => (Token::Else, text),
    r#"return"# => (Token::Return, text),

    r#"true"# => (Token::Bool(true), text),
    r#"false"# => (Token::Bool(false), text),
    // TODO: Deprecate/Remove?
    r#"True"# => (Token::Bool(true), text),
    r#"False"# => (Token::Bool(false), text),

    r#"\"([^\"]|(\\\"))*\""# => (
        Token::String(text.to_owned()[1..text.len()-1].replace("\\\"", "\"")),
        text
    ),
    r#"[0-9]+[\.]?[0-9]*"# => {
        let tok = match text.parse() {
            Ok(n) => Token::Number(n),
            Err(e) => panic!("Integer {text} is out of range: {e}"),
        };
        (tok, text)
    }

    r#"[a-zA-Z_][a-zA-Z0-9_]*"# => (Token::Ident(text.to_owned()), text),

    r#"=="# => (Token::Equals, text),
    r#"="# => (Token::Assign, text),
    r#"\+"# => (Token::Plus, text),
    r#"-"# => (Token::Minus, text),
    r#"\*"# => (Token::Star, text),
    r#"/"# => (Token::Slash, text),
    r#"%"# => (Token::Percent, text),
    r#"\("# => (Token::LParen, text),
    r#"\)"# => (Token::RParen, text),
    r#"\["# => (Token::LBracket, text),
    r#"\]"# => (Token::RBracket, text),
    r#"\{"# => (Token::LBrace, text),
    r#"\}"# => (Token::RBrace, text),
    r#","# => (Token::Comma, text),
    r#":"# => (Token::Colon, text),
    r#";"# => (Token::Semi, text),
}

pub struct Lexer<'a> {
    original: &'a str,
    remaining: &'a str,
    line: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(s: &'a str) -> Lexer<'a> {
        Lexer {
            original: s,
            remaining: s,
            line: 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Span {
    pub lo: usize,
    pub hi: usize,
    pub line: usize,
}

fn span_in(s: &str, t: &str, l: usize) -> Span {
    let lo = s.as_ptr() as usize - t.as_ptr() as usize;
    Span {
        lo,
        hi: lo + s.len(),
        line: l,
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = (Token, Span);
    fn next(&mut self) -> Option<(Token, Span)> {
        loop {
            let tok = if let Some((tok, new_remaining)) = next_token(self.remaining) {
                self.remaining = new_remaining;
                tok
            } else {
                return None;
            };
            match tok {
                (Token::Whitespace, _) | (Token::Comment, _) => {
                    continue;
                }
                (Token::Newline, _) => {
                    self.line += 1;
                    continue;
                }
                (tok, span) => {
                    return Some((tok, span_in(span, self.original, self.line)));
                }
            }
        }
    }
}

pub(crate) struct ControlledLexer<'a> {
    text: &'a str,
    offset: usize,
    line: usize,
    control: &'a aw_models::QueryControl,
    error: Option<aw_models::ReportExecutionErrorV1>,
}
impl<'a> ControlledLexer<'a> {
    pub(crate) fn new(
        text: &'a str,
        control: &'a aw_models::QueryControl,
    ) -> Result<Self, aw_models::ReportExecutionErrorV1> {
        if text.len() > aw_models::QueryLimits::MANAGED.max_query_bytes {
            return Err(aw_models::ReportExecutionErrorV1::ByteLimit);
        }
        control.charge_bytes(text.len() as u64)?;
        Ok(Self {
            text,
            offset: 0,
            line: 1,
            control,
            error: None,
        })
    }
    pub(crate) fn error(&self) -> Option<aw_models::ReportExecutionErrorV1> {
        self.error
    }
    fn token(&mut self) -> Result<Option<(Token, Span)>, aw_models::ReportExecutionErrorV1> {
        use aw_models::ReportExecutionErrorV1 as Error;
        loop {
            self.control.checkpoint()?;
            if let Some(error) = crate::parser::construction_error() {
                return Err(error);
            }
            let Some(byte) = self.text.as_bytes().get(self.offset).copied() else {
                return Ok(None);
            };
            self.control.charge_fuel(1)?;
            if byte.is_ascii_whitespace() {
                if byte == b'\n' {
                    self.line += 1;
                }
                self.offset += 1;
                continue;
            }
            if byte == b'#' {
                while self
                    .text
                    .as_bytes()
                    .get(self.offset)
                    .is_some_and(|b| *b != b'\n')
                {
                    self.control.charge_fuel(1)?;
                    self.offset += 1;
                }
                continue;
            }
            break;
        }
        self.control.charge_values(1)?;
        self.control.charge_bytes(
            (std::mem::size_of::<Token>()
                + std::mem::size_of::<Span>()
                + 3 * std::mem::size_of::<usize>()) as u64,
        )?;
        let start = self.offset;
        let first = self.text.as_bytes()[start];
        let token = if first == b'"' {
            let mut end = start + 1;
            let mut escaped = false;
            let mut closed = false;
            while let Some(byte) = self.text.as_bytes().get(end).copied() {
                self.control.charge_fuel(1)?;
                if !escaped && byte == b'"' {
                    end += 1;
                    closed = true;
                    break;
                }
                if !escaped && byte == b'\\' {
                    escaped = true;
                } else {
                    escaped = false;
                }
                end += 1;
            }
            if !closed {
                return Err(Error::InternalError);
            }
            self.control.charge_bytes((end - start) as u64)?;
            let value =
                serde_json::from_str(&self.text[start..end]).map_err(|_| Error::InternalError)?;
            self.offset = end;
            Token::String(value)
        } else if first.is_ascii_alphabetic() || first == b'_' {
            self.offset += 1;
            while self
                .text
                .as_bytes()
                .get(self.offset)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                self.control.charge_fuel(1)?;
                self.offset += 1;
            }
            let word = &self.text[start..self.offset];
            match word {
                "if" => Token::If,
                "elif" => Token::ElseIf,
                "else" => Token::Else,
                "return" => Token::Return,
                "true" | "True" => Token::Bool(true),
                "false" | "False" => Token::Bool(false),
                _ => {
                    self.control.charge_bytes(word.len() as u64)?;
                    Token::Ident(word.to_owned())
                }
            }
        } else if first.is_ascii_digit() {
            self.offset += 1;
            while self
                .text
                .as_bytes()
                .get(self.offset)
                .is_some_and(u8::is_ascii_digit)
            {
                self.control.charge_fuel(1)?;
                self.offset += 1;
            }
            if self.text.as_bytes().get(self.offset) == Some(&b'.') {
                self.offset += 1;
                while self
                    .text
                    .as_bytes()
                    .get(self.offset)
                    .is_some_and(u8::is_ascii_digit)
                {
                    self.control.charge_fuel(1)?;
                    self.offset += 1;
                }
            }
            let number: f64 = self.text[start..self.offset]
                .parse()
                .map_err(|_| Error::InternalError)?;
            if !number.is_finite() {
                return Err(Error::InternalError);
            }
            Token::Number(number)
        } else {
            self.offset += 1;
            match first {
                b'=' if self.text.as_bytes().get(self.offset) == Some(&b'=') => {
                    self.offset += 1;
                    Token::Equals
                }
                b'=' => Token::Assign,
                b'+' => Token::Plus,
                b'-' => Token::Minus,
                b'*' => Token::Star,
                b'/' => Token::Slash,
                b'%' => Token::Percent,
                b'(' => Token::LParen,
                b')' => Token::RParen,
                b'[' => Token::LBracket,
                b']' => Token::RBracket,
                b'{' => Token::LBrace,
                b'}' => Token::RBrace,
                b',' => Token::Comma,
                b':' => Token::Colon,
                b';' => Token::Semi,
                _ => return Err(Error::InternalError),
            }
        };
        Ok(Some((
            token,
            Span {
                lo: start,
                hi: self.offset,
                line: self.line,
            },
        )))
    }
}
impl Iterator for ControlledLexer<'_> {
    type Item = (Token, Span);
    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() {
            return None;
        }
        match self.token() {
            Ok(token) => token,
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }
}
