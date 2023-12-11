use colored::Colorize;
use selinux_event::Rule;

mod selinux_event {
    use crate::my_parser::ActionVerdict;
    use serde::Deserialize;

    #[derive(Debug)]
    pub struct LogDetails {
        pub log_type: String,
        pub msg_ts: f64,
        pub msg_id: u64,
    }

    pub trait Event: std::fmt::Display {
        fn match_rule(&self, rule: &Rule) -> bool;
    }

    #[derive(Debug)]
    pub struct AvcEvent {
        pub details: LogDetails,
        pub verdict: ActionVerdict,
        pub actions: Vec<String>,
        pub fields: Vec<Field>,
    }

    impl Event for AvcEvent {
        fn match_rule(&self, rule: &Rule) -> bool {
            if let Some(log_type) = &rule.event_type {
                if log_type.clone() != self.details.log_type {
                    return false;
                }
            }
            if let Some(verdict) = &rule.verdict {
                match self.verdict {
                    ActionVerdict::Granted => {
                        if verdict != "granted" {
                            return false;
                        }
                    }
                    ActionVerdict::Denied => {
                        if verdict != "denied" {
                            return false;
                        }
                    }
                }
            }
            if let Some(actions) = &rule.actions {
                if actions.iter().any(|a| !self.actions.contains(a)) {
                    return false;
                }
            }
            if let Some(fields) = &rule.fields {
                if fields.iter().any(|a| !self.fields.contains(a)) {
                    return false;
                }
            }
            true
        }
    }

    #[derive(Debug)]
    pub struct NormalEvent {
        pub details: LogDetails,
        pub fields: Vec<Field>,
    }

    impl std::fmt::Display for AvcEvent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let _var_name = write!(
                f,
                "AvcEvent {{ details={} verdict={} actions=[",
                self.details, self.verdict
            );
            self.actions.iter().for_each(|a| {
                let _var_name = write!(f, "{},", a);
            });
            let _var_name = write!(f, "] fields=[");
            self.fields.iter().for_each(|field| {
                let _var_name = write!(f, "{}, ", field);
            });
            write!(f, "]}}")
        }
    }
    impl std::fmt::Display for NormalEvent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let _var_name = write!(f, "Normal Event {{ details={} fields=[", self.details);
            self.fields.iter().for_each(|field| {
                let _var_name = write!(f, "{}, ", field);
            });
            write!(f, "]}}")
        }
    }
    impl std::fmt::Display for LogDetails {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "type={} ts={} id={}",
                self.log_type, self.msg_ts, self.msg_id
            )
        }
    }
    impl std::fmt::Display for Field {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Field {{name={} value{}}}", self.name, self.value)
        }
    }

    impl Event for NormalEvent {
        fn match_rule(&self, rule: &Rule) -> bool {
            if let Some(log_type) = &rule.event_type {
                if log_type.clone() != self.details.log_type {
                    return false;
                }
            }

            if let Some(fields) = &rule.fields {
                if fields.iter().any(|a| !self.fields.contains(a)) {
                    return false;
                }
            }
            true
        }
    }

    #[derive(Debug, Deserialize, PartialEq)]
    pub struct Field {
        pub name: String,
        pub value: FieldValue,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(untagged)]
    pub enum FieldValue {
        Int(u64),
        Float(f64),
        String(String),
    }

    impl std::fmt::Display for FieldValue {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                FieldValue::Int(i) => write!(f, "{}", i),
                FieldValue::Float(float) => write!(f, "{}", float),
                FieldValue::String(s) => write!(f, "{}", s),
            }
        }
    }

    #[derive(Deserialize)]
    pub struct Rule {
        event_type: Option<String>,
        actions: Option<Vec<String>>,
        verdict: Option<String>,
        fields: Option<Vec<Field>>,
    }

    impl std::fmt::Display for Rule {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let _var_name = write!(f, "Rule {{");
            if let Some(event_type) = &self.event_type {
                let _var_name = write!(f, "event_type={} ", event_type);
            }
            if let Some(actions) = &self.actions {
                let _var_name = write!(f, "actions=[");
                actions.iter().for_each(|a| {
                    let _var_name = write!(f, "{},", a);
                });
                let _var_name = write!(f, "] ");
            }

            if let Some(verdict) = &self.verdict {
                let _var_name = write!(f, "verdict={} ", verdict);
            }

            if let Some(fields) = &self.fields {
                let _var_name = write!(f, "fields=[");
                fields.iter().for_each(|a| {
                    let _var_name = write!(f, "{},", a);
                });
                let _var_name = write!(f, "]");
            }
            write!(f, "}}")
        }
    }
}

mod my_parser {
    pub struct Parser {
        pub input: Vec<Token>,
        idx: usize,
    }

    impl Parser {
        fn consume(&mut self, t: Token) -> Token {
            if self.input[self.idx] != t {
                panic!("Expected {:?} but received {:?}", t, self.input[self.idx]);
            }
            self.idx += 1;
            t
        }

        fn match_token(&mut self, t: Token) -> bool {
            self.input[self.idx] == t
        }

        fn avc_event(&mut self) -> AvcEvent {
            let details = self.log_details();
            self.consume(Token::Colon);
            self.consume(Token::AvcLower);
            let verdict = match &self.input[self.idx] {
                Token::Action(v) => v.clone(),
                _ => panic!("Expected verdict"),
            };
            self.idx += 1;
            let actions = self.actions();
            self.consume(Token::For);
            let fields = self.event_fields();
            AvcEvent {
                details,
                verdict,
                actions,
                fields,
            }
        }

        fn normal_event(&mut self) -> NormalEvent {
            let details = self.log_details();
            self.consume(Token::Colon);
            let fields = self.event_fields();
            NormalEvent { details, fields }
        }

        fn log_details(&mut self) -> LogDetails {
            self.idx += 1;
            let ret = LogDetails {
                log_type: match &self.input[self.idx - 1] {
                    Token::AvcUpper => "AVC".to_string(),
                    Token::Identifier(s) => s.clone(),
                    _ => panic!("Unknown event type"),
                },
                msg_ts: self.msg_ts(),
                msg_id: self.msg_id(),
            };
            self.consume(Token::RParen);
            ret
        }

        fn msg_ts(&mut self) -> f64 {
            self.consume(Token::Msg);
            self.consume(Token::Equal);
            self.consume(Token::Audit);
            self.consume(Token::LParen);
            if let Token::Float(f) = self.input[self.idx] {
                self.idx += 1;
                f
            } else {
                panic!("Expected msg_ts as float");
            }
        }

        fn msg_id(&mut self) -> u64 {
            self.consume(Token::Colon);
            if let Token::Int(x) = self.input[self.idx] {
                self.idx += 1;
                x
            } else {
                panic!("Expected msg_ts as float");
            }
        }

        fn actions(&mut self) -> Vec<String> {
            self.consume(Token::LBrace);
            let mut res: Vec<String> = vec![];
            while let Token::Identifier(s) = &self.input[self.idx] {
                self.idx += 1;
                res.push(s.clone());
            }
            self.consume(Token::RBrace);
            res
        }

        fn event_fields(&mut self) -> Vec<Field> {
            let mut res: Vec<Field> = vec![];
            while self.idx < self.input.len() {
                if let Token::Identifier(id) = &self.input[self.idx].clone() {
                    self.idx += 1;
                    self.consume(Token::Equal);
                    let val = match &self.input[self.idx] {
                        Token::Identifier(v) => FieldValue::String(v.clone()),
                        Token::Int(i) => FieldValue::Int(*i),
                        Token::Float(f) => FieldValue::Float(*f),
                        Token::String(s) => FieldValue::String(s.clone()),
                        f => panic!("Field can take value string, int and float only {:?}", f),
                    };
                    res.push(Field {
                        name: id.clone(),
                        value: val,
                    });
                }
                self.idx += 1;
            }
            res
        }
        pub fn new(input: Vec<Token>) -> Parser {
            Parser { input, idx: 0 }
        }

        pub fn parse(&mut self) -> Box<dyn crate::selinux_event::Event> {
            self.consume(Token::Type);
            self.consume(Token::Equal);
            if self.match_token(Token::AvcUpper) {
                Box::new(self.avc_event())
            } else {
                Box::new(self.normal_event())
            }
        }
    }
    use core::fmt;
    use std::collections::HashMap;

    use crate::selinux_event::{AvcEvent, Field, FieldValue, LogDetails, NormalEvent};
    #[derive(Debug, Clone, PartialEq)]
    pub enum Token {
        AvcUpper,
        AvcLower,
        Int(u64),
        Float(f64),
        String(String),
        LParen,
        RParen,
        LBrace,
        RBrace,
        Dot,
        Identifier(String),
        Action(ActionVerdict),
        Type,
        Msg,
        Audit,
        Colon,
        Equal,
        For,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum ActionVerdict {
        Granted,
        Denied,
    }

    impl fmt::Display for ActionVerdict {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ActionVerdict::Granted => write!(f, "granted"),
                ActionVerdict::Denied => write!(f, "denied"),
            }
        }
    }
    pub fn scan(input: String) -> Vec<Token> {
        let keywords: HashMap<String, Token> = vec![
            ("type".to_string(), Token::Type),
            ("msg".to_string(), Token::Msg),
            ("audit".to_string(), Token::Audit),
            ("denied".to_string(), Token::Action(ActionVerdict::Denied)),
            ("granted".to_string(), Token::Action(ActionVerdict::Granted)),
            ("AVC".to_string(), Token::AvcUpper),
            ("avc:".to_string(), Token::AvcLower),
            ("for".to_string(), Token::For),
        ]
        .into_iter()
        .collect();

        let input: Vec<char> = input.chars().collect();
        let mut res: Vec<Token> = vec![];
        let mut idx = 0;
        while idx < input.len() {
            match input[idx] {
                '=' => {
                    res.push(Token::Equal);
                }
                ':' => {
                    res.push(Token::Colon);
                }
                '\'' => {
                    let start_idx = idx;
                    idx += 1;
                    while input[idx] != '\'' {
                        idx += 1;
                    }
                    let string: String = input[(start_idx + 1)..idx].iter().collect();
                    let next = Token::String(string);
                    res.push(next);
                }
                '"' => {
                    let start_idx = idx;
                    idx += 1;
                    while input[idx] != '"' {
                        idx += 1;
                    }
                    let string: String = input[(start_idx + 1)..idx].iter().collect();
                    let next = Token::String(string);
                    res.push(next);
                }
                '(' => {
                    if res.last().unwrap().clone() == Token::Equal {
                    } else {
                        res.push(Token::LParen);
                    }
                }
                ')' => res.push(Token::RParen),
                '.' => res.push(Token::Dot),
                '{' => res.push(Token::LBrace),
                '}' => res.push(Token::RBrace),
                '\n' => panic!("Expected a single log line, found newline in input"),
                c => {
                    if c == '0' && idx < input.len() && input[idx + 1] == 'x' {
                        let start_idx = idx + 2;
                        while idx < input.len() && input[idx] != ' ' {
                            idx += 1;
                        }

                        let string: String = input[start_idx..idx].iter().collect();
                        if string.chars().all(|c| c.is_ascii_hexdigit()) {
                            res.push(Token::Int(u64::from_str_radix(&string, 16).unwrap()));
                        } else {
                            res.push(Token::String("0x".to_string() + string.as_str()));
                        }
                    } else if c.is_ascii_digit() {
                        let start_idx = idx;
                        idx += 1;
                        while idx < input.len() && input[idx].is_ascii_hexdigit() {
                            idx += 1;
                        }
                        if idx < input.len() && input[idx] == '.' {
                            idx += 1;
                            while idx < input.len() && input[idx].is_ascii_digit() {
                                idx += 1;
                            }
                            if input[idx] == ':' {
                                let string: String = input[(start_idx)..idx].iter().collect();
                                res.push(Token::Float(string.parse::<f64>().unwrap()));
                            } else if input[idx] == ' ' {
                                let string: String = input[(start_idx)..idx].iter().collect();
                                res.push(Token::Float(string.parse::<f64>().unwrap()))
                            } else {
                                let allowed: Vec<char> = (b'a'..=b'z')
                                    .chain(b'A'..=b'Z')
                                    .chain(b'0'..=b'9')
                                    .chain([b':', b'_', b'.', b'-'].iter().copied())
                                    .map(|c| c as char)
                                    .collect();
                                while idx < input.len() && allowed.contains(&input[idx]) {
                                    idx += 1;
                                }
                                let string: String = input[(start_idx)..idx].iter().collect();
                                if keywords.contains_key(&string) {
                                    let next = keywords.get(&string).unwrap().clone();
                                    res.push(next);
                                } else {
                                    res.push(Token::Identifier(string));
                                }
                                idx -= 1;
                            }
                        } else {
                            let string: String = input[(start_idx)..idx].iter().collect();
                            if string.chars().all(|c| c.is_ascii_digit()) {
                                res.push(Token::Int(string.parse::<u64>().unwrap()));
                            } else {
                                res.push(Token::String(string));
                            }
                        }
                        idx -= 1; // go back one such that this char will be processed too
                    } else if c.is_alphabetic() {
                        let allowed: Vec<char> = (b'a'..=b'z')
                            .chain(b'A'..=b'Z')
                            .chain(b'0'..=b'9')
                            .chain([b':', b'_', b'.', b'-'].iter().copied())
                            .map(|c| c as char)
                            .collect();
                        let start_idx = idx;
                        while idx < input.len() && allowed.contains(&input[idx]) {
                            idx += 1;
                        }
                        let string: String = input[(start_idx)..idx].iter().collect();
                        if keywords.contains_key(&string) {
                            let next = keywords.get(&string).unwrap().clone();
                            res.push(next);
                        } else {
                            res.push(Token::Identifier(string));
                        }
                        idx -= 1;
                    }
                }
            };
            idx += 1;
        }
        res
    }
}

fn main() {
    let rules_file = std::fs::read_to_string("rules.yaml").expect("Rules file not found");

    let rules: Vec<Rule> = serde_yaml::from_str(&rules_file).unwrap();
    std::fs::read_to_string("audit.log")
        .expect("audit.log not found")
        .lines()
        .map(|line| my_parser::scan(line.to_string()))
        .map(|tokens| my_parser::Parser::new(tokens).parse())
        .for_each(|event| {
            rules.iter().for_each(|rule| {
                if event.match_rule(rule) {
                    let msg = format!("Event: {} matched rule: {}", event, rule);
                    println!("{}", msg.red());
                }
            })
        });
}
