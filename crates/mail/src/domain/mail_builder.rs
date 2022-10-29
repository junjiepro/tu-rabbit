//! 邮件

use lettre_email::EmailBuilder;

pub struct MailBuilder {
    to: Vec<String>,
    subject: Option<String>,
    content: Option<MailType>,
}

pub enum MailType {
    Text(String),
    Html(String),
}

impl MailBuilder {
    pub fn new() -> MailBuilder {
        MailBuilder {
            to: vec![],
            subject: None,
            content: None,
        }
    }

    pub fn to<A: Into<String>>(mut self, to: A) -> MailBuilder {
        self.to.push(to.into());
        self
    }

    pub fn subject<A: Into<String>>(mut self, subject: A) -> MailBuilder {
        self.subject = Some(subject.into());
        self
    }

    pub fn text<A: Into<String>>(mut self, content: A) -> MailBuilder {
        self.content = Some(MailType::Text(content.into()));
        self
    }

    pub fn html<A: Into<String>>(mut self, content: A) -> MailBuilder {
        self.content = Some(MailType::Html(content.into()));
        self
    }

    pub(crate) fn to_email_builder(self) -> EmailBuilder {
        let builder = self.to
            .into_iter()
            .fold(
                EmailBuilder::new(),
                |builder, t| builder.to(t)
            );
        
        let builder = {
            if self.subject.is_some() {
                builder.subject(self.subject.unwrap())
            } else {
                builder
            }
        };
        let builder = {
            if self.content.is_some() {
                match self.content.unwrap() {
                    MailType::Text(content) => {
                        let builder = builder.text(content);
                        builder
                    },
                    MailType::Html(content) => {
                        let builder = builder.html(content);
                        builder
                    },
                }
            } else {
                builder
            }
        };

        builder
    }
}