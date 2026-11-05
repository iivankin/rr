//! HTTP/1.1 client side (RFC 9112) without I/O: a request written into
//! the caller's buffer, and a response parsed from whatever pieces the
//! caller reads, down to one byte at a time. The head is copied once into
//! the parser, which keeps it until the next response; body bytes come
//! back as slices of the caller's input and are never copied. Each byte
//! is looked at once: a piece that ends inside a line or a chunk's
//! framing resumes where it stopped.

use alloc::vec::Vec;

/// The most bytes of heads one response may carry: interim heads, the
/// final head and the trailers together.
pub const HEAD_MAX: usize = 64 * 1024;
/// The most header fields of one head.
pub const HEADERS_MAX: usize = 128;
/// The most bytes of a chunk-size line with its extensions.
const CHUNK_LINE_MAX: usize = 4096;

#[derive(Clone, Copy)]
#[cfg_attr(any(test, fuzzing), derive(Debug, PartialEq))]
pub enum Error {
    /// A request field holds a byte its grammar does not allow, CR, LF
    /// and NUL among them, or names a header the framing writes.
    Field,
    /// The status line is not HTTP/1.0 or 1.1 with a code of 100 to 599.
    Status,
    /// A header line is malformed or holds a control byte such as NUL.
    Header,
    /// A header line continues the one before it (obs-fold).
    Fold,
    /// The heads passed HEAD_MAX bytes or HEADERS_MAX fields.
    TooLarge,
    /// Content-Length is not a number, or two of them differ.
    Length,
    /// Transfer-Encoding does not end in chunked, names it twice, comes
    /// with Content-Length or in an HTTP/1.0 response.
    Coding,
    /// A chunk-size line or the line end after a chunk is malformed.
    Chunk,
    /// The connection closed inside the response.
    Truncated,
    /// The connection closed before any byte of the response: on a reused
    /// connection the server had dropped it, and a request that may be
    /// repeated goes again on a new one.
    Closed,
}

/// How the request's body is framed. The caller sends the body after
/// the head; chunks are written by chunk and last_chunk.
pub enum Body {
    /// No body and no framing header, as a GET has.
    None,
    Length(u64),
    Chunked,
}

/// What a call to Response::feed found.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Event<'a> {
    /// All the input was taken; read more and feed again.
    Need,
    /// The final head is complete: status and headers can be read.
    Head,
    /// Body bytes, a slice of the input.
    Body(&'a [u8]),
    /// The response is complete. Input past the count consumed belongs
    /// to the next response on the connection.
    End,
}

/// Writes a request head into out: the request line, Host, the caller's
/// headers and the body's framing header. A field that could end a line
/// or forge another header is refused, and out is then left as it was;
/// so are Host, Content-Length and Transfer-Encoding among the headers,
/// which this writes itself.
pub fn request(
    out: &mut Vec<u8>,
    method: &[u8],
    target: &[u8],
    host: &[u8],
    headers: &[(&[u8], &[u8])],
    body: &Body,
) -> Result<(), Error> {
    if !is_token(method) || !visible(target) || !visible(host) {
        return Err(Error::Field);
    }
    for (name, value) in headers {
        if !is_token(name) || !value.iter().all(|byte| field_byte(*byte)) {
            return Err(Error::Field);
        }
        if [&b"host"[..], b"content-length", b"transfer-encoding"]
            .iter()
            .any(|framing| name.eq_ignore_ascii_case(framing))
        {
            return Err(Error::Field);
        }
    }
    out.extend_from_slice(method);
    out.push(b' ');
    out.extend_from_slice(target);
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host);
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    match body {
        Body::None => {}
        Body::Length(length) => {
            out.extend_from_slice(b"Content-Length: ");
            number(out, *length, 10);
            out.extend_from_slice(b"\r\n");
        }
        Body::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// Writes the line that starts a chunk of size bytes: the caller sends
/// the bytes and then CRLF. A size of 0 would end the body: last_chunk.
pub fn chunk_head(out: &mut Vec<u8>, size: usize) {
    number(out, size as u64, 16);
    out.extend_from_slice(b"\r\n");
}

/// Writes data as one chunk, copied; nothing when it is empty, since an
/// empty chunk ends the body.
pub fn chunk(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    chunk_head(out, data.len());
    // The chunk is written whole for a caller that sends one buffer;
    // chunk_head spares the copy.
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// Writes the last chunk, which ends a chunked body, with no trailers.
pub fn last_chunk(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0\r\n\r\n");
}

/// value in the radix given, 10 or 16, without leading zeros.
fn number(out: &mut Vec<u8>, value: u64, radix: u64) {
    let mut digits = [0_u8; 20];
    let mut used = 0;
    let mut rest = value;
    for slot in digits.iter_mut().rev() {
        *slot = b"0123456789abcdef"
            .get(usize::try_from(rest % radix).unwrap_or(0))
            .copied()
            .unwrap_or(b'0');
        rest /= radix;
        used += 1;
        if rest == 0 {
            break;
        }
    }
    let start = digits.len().saturating_sub(used);
    out.extend_from_slice(digits.get(start..).unwrap_or_default());
}

/// Bytes of a token (RFC 9110 section 5.6.2): a method or a field name.
fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| token_byte(*byte))
}

/// A target or a host: printable ASCII, no space.
fn visible(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| (0x21..0x7f).contains(byte))
}

/// A byte a field value or a reason may hold: no control but HTAB.
fn field_byte(byte: u8) -> bool {
    byte == b'\t' || (byte >= 0x20 && byte != 0x7f)
}

#[derive(Clone, Copy)]
enum State {
    Head,
    /// Body bytes left of a Content-Length.
    Length(u64),
    /// The body ends when the connection does.
    Close,
    /// Inside a chunk's framing.
    Chunk(Frame),
    /// Bytes left of a chunk's data.
    Data(u64),
    Done,
    Failed(Error),
}

/// Where in the framing of a chunked body the parser is; the u64 is the
/// size read so far.
#[derive(Clone, Copy)]
enum Frame {
    Size(u64),
    /// Whitespace after the size, before an extension or the line end.
    Space(u64),
    /// An extension, skipped to the line end.
    Extension(u64),
    SizeLf(u64),
    /// The CRLF after a chunk's data.
    DataCr,
    DataLf,
    /// The start of a trailer line or of the blank line that ends.
    LineStart,
    Trailer,
    TrailerLf,
    EndLf,
}

/// What one byte of framing leads to.
enum Step {
    Frame(Frame),
    Data(u64),
    Done,
}

#[derive(Clone, Copy)]
enum Coding {
    None,
    Chunked,
    /// A coding other than chunked last.
    Other,
}

#[derive(Clone, Copy)]
enum Connection {
    /// What the version says: persistent in 1.1, not in 1.0.
    Default,
    Close,
    KeepAlive,
}

/// The headers that frame the message, as the head's lines give them.
struct Framing {
    length: Option<u64>,
    coding: Coding,
    connection: Connection,
}

/// A header line's place in the head: the name and the trimmed value.
struct Field {
    name: (usize, usize),
    value: (usize, usize),
}

/// An HTTP/1.1 response being parsed. One serves every response of a
/// connection: restart between them keeps its buffers.
pub struct Response {
    state: State,
    /// The head's bytes so far; the line being read starts at line.
    head: Vec<u8>,
    line: usize,
    fields: Vec<Field>,
    /// Head and trailer bytes so far, interim heads among them.
    seen: usize,
    /// Bytes of the chunk-size line so far.
    chunk_line: usize,
    status: u16,
    /// The minor version: 0 or 1.
    minor: u8,
    framing: Framing,
    head_request: bool,
    reusable: bool,
}

impl Response {
    /// A parser for the response to a request; head_request when it was
    /// HEAD, whose response has no body whatever its headers say.
    pub fn new(head_request: bool) -> Response {
        Response {
            state: State::Head,
            head: Vec::new(),
            line: 0,
            fields: Vec::new(),
            seen: 0,
            chunk_line: 0,
            status: 0,
            minor: 0,
            framing: Framing {
                length: None,
                coding: Coding::None,
                connection: Connection::Default,
            },
            head_request,
            reusable: false,
        }
    }

    /// Readies the parser for the next response on the connection.
    pub fn restart(&mut self, head_request: bool) {
        self.state = State::Head;
        self.head.clear();
        self.line = 0;
        self.fields.clear();
        self.seen = 0;
        self.chunk_line = 0;
        self.status = 0;
        self.minor = 0;
        self.framing = Framing {
            length: None,
            coding: Coding::None,
            connection: Connection::Default,
        };
        self.head_request = head_request;
        self.reusable = false;
    }

    /// Parses the start of input: how many bytes it took and what they
    /// held. Need takes all of it; the other events may leave a rest,
    /// which the caller feeds again. After End it returns End taking
    /// nothing, after an error the same error, until restart.
    #[cfg_attr(rr, rr::hot)]
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> Result<(usize, Event<'a>), Error> {
        let result = match self.state {
            State::Head => self.head_lines(input),
            State::Length(left) => {
                let (taken, piece) = take(input, left);
                let left = left.saturating_sub(taken as u64);
                self.state = if left == 0 {
                    State::Done
                } else {
                    State::Length(left)
                };
                Ok(body(taken, piece))
            }
            State::Close => Ok(body(input.len(), input)),
            State::Data(left) => Ok(self.data(input, left)),
            State::Chunk(frame) => self.framing_bytes(input, frame),
            State::Done => Ok((0, Event::End)),
            State::Failed(error) => Err(error),
        };
        if let Err(error) = result {
            self.state = State::Failed(error);
        }
        result
    }

    /// The connection closed: Ok when that ends the response, as it ends
    /// a body without a length.
    pub fn eof(&mut self) -> Result<(), Error> {
        match self.state {
            State::Close | State::Done => {
                self.state = State::Done;
                Ok(())
            }
            State::Failed(error) => Err(error),
            State::Head if self.seen == 0 => Err(Error::Closed),
            State::Head | State::Length(_) | State::Chunk(_) | State::Data(_) => {
                self.state = State::Failed(Error::Truncated);
                Err(Error::Truncated)
            }
        }
    }

    /// The final status code; 0 before the head.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The response's minor version: 1 for HTTP/1.1, 0 for 1.0.
    pub fn minor(&self) -> u8 {
        self.minor
    }

    /// The body's Content-Length, if the head gave one.
    pub fn length(&self) -> Option<u64> {
        self.framing.length
    }

    /// The value of the first header named name, in any case, trimmed.
    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        let mut at = 0;
        while let Some((field, value)) = self.header_at(at) {
            if field.eq_ignore_ascii_case(name) {
                return Some(value);
            }
            at += 1;
        }
        None
    }

    /// The number of header fields of the head.
    pub fn header_count(&self) -> usize {
        self.fields.len()
    }

    /// The name and value of the field at index at.
    pub fn header_at(&self, at: usize) -> Option<(&[u8], &[u8])> {
        let field = self.fields.get(at)?;
        let name = self.head.get(field.name.0..field.name.1)?;
        let value = self.head.get(field.value.0..field.value.1)?;
        Some((name, value))
    }

    /// Whether the connection may carry the next request: the response
    /// is complete, framed by its own length, and neither side asked to
    /// close it.
    pub fn reusable(&self) -> bool {
        matches!(self.state, State::Done) && self.reusable
    }

    /// Collects head lines up to the blank line that ends the final head.
    fn head_lines<'a>(&mut self, input: &'a [u8]) -> Result<(usize, Event<'a>), Error> {
        let mut taken = 0;
        while let Some(rest) = input.get(taken..) {
            let found = rest.iter().position(|byte| *byte == b'\n');
            let line = match found {
                Some(lf) => rest.get(..=lf).unwrap_or(rest),
                None => rest,
            };
            if line.len() > HEAD_MAX - self.seen {
                return Err(Error::TooLarge);
            }
            self.seen += line.len();
            taken += line.len();
            // rr: escape(copy, bound): a head may come a byte at a time, and
            // its lines wait here until it is whole; seen holds them to
            // HEAD_MAX just above.
            self.head.extend_from_slice(line);
            if found.is_none() {
                break;
            }
            if self.finish_line()? {
                return Ok((taken, Event::Head));
            }
        }
        Ok((taken, Event::Need))
    }

    /// Parses the line that ends the head buffer; true when it ended the
    /// final head.
    fn finish_line(&mut self) -> Result<bool, Error> {
        let start = self.line;
        let mut end = self.head.len().saturating_sub(1);
        if end > start && self.head.get(end - 1) == Some(&b'\r') {
            end -= 1;
        }
        self.line = self.head.len();
        let line = self.head.get(start..end).unwrap_or_default();
        if start == 0 {
            (self.minor, self.status) = status_line(line)?;
            return Ok(false);
        }
        if line.is_empty() {
            return self.finish_head();
        }
        if self.fields.len() >= HEADERS_MAX {
            return Err(Error::TooLarge);
        }
        let parsed = field(line, start)?;
        let name = self
            .head
            .get(parsed.name.0..parsed.name.1)
            .unwrap_or_default();
        let value = self
            .head
            .get(parsed.value.0..parsed.value.1)
            .unwrap_or_default();
        framing(&mut self.framing, name, value)?;
        self.fields.push(parsed);
        Ok(false)
    }

    /// Picks the body's framing once the head is whole; false after an
    /// interim response, whose head is dropped for the next one.
    fn finish_head(&mut self) -> Result<bool, Error> {
        if (100..200).contains(&self.status) && self.status != 101 {
            self.head.clear();
            self.fields.clear();
            self.line = 0;
            self.framing = Framing {
                length: None,
                coding: Coding::None,
                connection: Connection::Default,
            };
            return Ok(false);
        }
        self.reusable = match self.framing.connection {
            Connection::Default => self.minor == 1,
            Connection::Close => false,
            Connection::KeepAlive => true,
        };
        // After 101 the connection speaks another protocol.
        if self.status == 101 {
            self.reusable = false;
            self.state = State::Done;
            return Ok(true);
        }
        if self.head_request || matches!(self.status, 204 | 304) {
            self.state = State::Done;
            return Ok(true);
        }
        self.state = match self.framing.coding {
            Coding::Chunked => {
                if self.framing.length.is_some() || self.minor == 0 {
                    return Err(Error::Coding);
                }
                self.chunk_line = 0;
                State::Chunk(Frame::Size(0))
            }
            Coding::Other => return Err(Error::Coding),
            Coding::None => match self.framing.length {
                Some(0) => State::Done,
                Some(length) => State::Length(length),
                None => {
                    self.reusable = false;
                    State::Close
                }
            },
        };
        Ok(true)
    }

    /// The bytes of a chunk's data that input holds.
    fn data<'a>(&mut self, input: &'a [u8], left: u64) -> (usize, Event<'a>) {
        let (taken, piece) = take(input, left);
        let left = left.saturating_sub(taken as u64);
        self.state = if left == 0 {
            State::Chunk(Frame::DataCr)
        } else {
            State::Data(left)
        };
        body(taken, piece)
    }

    /// Walks chunk framing a byte at a time, up to the next data, which
    /// it returns in the same call, or to the end.
    fn framing_bytes<'a>(
        &mut self,
        input: &'a [u8],
        frame: Frame,
    ) -> Result<(usize, Event<'a>), Error> {
        let mut frame = frame;
        for (at, byte) in input.iter().enumerate() {
            match self.frame(frame, *byte)? {
                Step::Frame(next) => frame = next,
                Step::Data(size) => {
                    let rest = input.get(at + 1..).unwrap_or_default();
                    let (taken, event) = self.data(rest, size);
                    return Ok((at + 1 + taken, event));
                }
                Step::Done => {
                    self.state = State::Done;
                    return Ok((at + 1, Event::End));
                }
            }
        }
        self.state = State::Chunk(frame);
        Ok((input.len(), Event::Need))
    }

    /// One byte of chunk framing (RFC 9112 section 7.1). A bare LF ends a
    /// line as CRLF does; a bare CR is refused.
    fn frame(&mut self, frame: Frame, byte: u8) -> Result<Step, Error> {
        match frame {
            Frame::Size(_) | Frame::Space(_) | Frame::Extension(_) | Frame::SizeLf(_) => {
                self.chunk_line += 1;
                if self.chunk_line > CHUNK_LINE_MAX {
                    return Err(Error::Chunk);
                }
            }
            Frame::LineStart | Frame::Trailer | Frame::TrailerLf | Frame::EndLf => {
                if self.seen >= HEAD_MAX {
                    return Err(Error::TooLarge);
                }
                self.seen += 1;
            }
            Frame::DataCr | Frame::DataLf => {}
        }
        let next = match (frame, byte) {
            (Frame::Size(size), b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F') => {
                if size > u64::MAX >> 4 {
                    return Err(Error::Chunk);
                }
                let digit = match byte {
                    b'0'..=b'9' => byte - b'0',
                    _ => (byte | 0x20) - b'a' + 10,
                };
                Frame::Size((size << 4) | u64::from(digit))
            }
            (Frame::Size(_), _) if self.chunk_line == 1 => return Err(Error::Chunk),
            (Frame::Size(size) | Frame::Space(size), b' ' | b'\t') => Frame::Space(size),
            (Frame::Size(size) | Frame::Space(size), b';') => Frame::Extension(size),
            (Frame::Extension(size), byte) if byte != b'\r' && byte != b'\n' => {
                if !field_byte(byte) {
                    return Err(Error::Chunk);
                }
                Frame::Extension(size)
            }
            (Frame::Size(size) | Frame::Space(size) | Frame::Extension(size), b'\r') => {
                Frame::SizeLf(size)
            }
            (
                Frame::Size(size)
                | Frame::Space(size)
                | Frame::Extension(size)
                | Frame::SizeLf(size),
                b'\n',
            ) => {
                self.chunk_line = 0;
                return Ok(if size == 0 {
                    Step::Frame(Frame::LineStart)
                } else {
                    Step::Data(size)
                });
            }
            (Frame::DataCr, b'\r') => Frame::DataLf,
            (Frame::DataCr | Frame::DataLf, b'\n') => Frame::Size(0),
            (Frame::LineStart, b'\r') => Frame::EndLf,
            (Frame::LineStart | Frame::EndLf, b'\n') => return Ok(Step::Done),
            (Frame::Trailer | Frame::TrailerLf, b'\n') => Frame::LineStart,
            (Frame::Trailer, b'\r') => Frame::TrailerLf,
            (Frame::LineStart | Frame::Trailer, byte) if field_byte(byte) => Frame::Trailer,
            (Frame::LineStart | Frame::Trailer | Frame::TrailerLf, _) => {
                return Err(Error::Header);
            }
            (
                Frame::Size(_)
                | Frame::Space(_)
                | Frame::Extension(_)
                | Frame::SizeLf(_)
                | Frame::DataCr
                | Frame::DataLf
                | Frame::EndLf,
                _,
            ) => return Err(Error::Chunk),
        };
        Ok(Step::Frame(next))
    }
}

/// The start of input, up to left bytes, and its length.
fn take(input: &[u8], left: u64) -> (usize, &[u8]) {
    let taken = usize::try_from(left).map_or(input.len(), |left| left.min(input.len()));
    (taken, input.get(..taken).unwrap_or_default())
}

/// A piece of body, or Need when there is none.
fn body(taken: usize, piece: &[u8]) -> (usize, Event<'_>) {
    if piece.is_empty() {
        (taken, Event::Need)
    } else {
        (taken, Event::Body(piece))
    }
}

/// "HTTP/1.1 200 OK": the minor version and the code. The reason may be
/// absent, with or without the space before it.
fn status_line(line: &[u8]) -> Result<(u8, u16), Error> {
    let (version, rest) = line.split_at_checked(8).ok_or(Error::Status)?;
    let minor = match version {
        b"HTTP/1.0" => 0,
        b"HTTP/1.1" => 1,
        _ => return Err(Error::Status),
    };
    let [b' ', hundreds, tens, ones, reason @ ..] = rest else {
        return Err(Error::Status);
    };
    let mut status = 0;
    for digit in [hundreds, tens, ones] {
        if !digit.is_ascii_digit() {
            return Err(Error::Status);
        }
        status = status * 10 + u16::from(digit - b'0');
    }
    if !(100..600).contains(&status) {
        return Err(Error::Status);
    }
    match reason.split_first() {
        None => {}
        Some((b' ', text)) if text.iter().all(|byte| field_byte(*byte)) => {}
        Some(_) => return Err(Error::Status),
    }
    Ok((minor, status))
}

/// The name and trimmed value of a header line that starts at start in
/// the head. No space may come before the colon, nor start the line.
fn field(line: &[u8], start: usize) -> Result<Field, Error> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(Error::Fold);
    }
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(Error::Header)?;
    if !is_token(line.get(..colon).unwrap_or_default()) {
        return Err(Error::Header);
    }
    let value = line.get(colon + 1..).unwrap_or_default();
    if !value.iter().all(|byte| field_byte(*byte)) {
        return Err(Error::Header);
    }
    let first = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let last = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(first, |at| at + 1);
    let value_start = start + colon + 1;
    Ok(Field {
        name: (start, start + colon),
        value: (value_start + first, value_start + last),
    })
}

/// Notes what a header says about framing and the connection.
fn framing(framing: &mut Framing, name: &[u8], value: &[u8]) -> Result<(), Error> {
    if name.eq_ignore_ascii_case(b"content-length") {
        // A list of the same length, or the same header twice, is one
        // length (RFC 9110 section 8.6); two lengths are an attack.
        for item in value.split(|byte| *byte == b',') {
            let length = decimal(item.trim_ascii()).ok_or(Error::Length)?;
            if framing.length.is_some_and(|before| before != length) {
                return Err(Error::Length);
            }
            framing.length = Some(length);
        }
    } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
        let mut any = false;
        for coding in value.split(|byte| *byte == b',') {
            let coding = coding.trim_ascii();
            if coding.is_empty() {
                continue;
            }
            any = true;
            // Nothing may follow chunked, which is applied once and last.
            if matches!(framing.coding, Coding::Chunked) {
                return Err(Error::Coding);
            }
            framing.coding = if coding.eq_ignore_ascii_case(b"chunked") {
                Coding::Chunked
            } else {
                Coding::Other
            };
        }
        if !any {
            return Err(Error::Coding);
        }
    } else if name.eq_ignore_ascii_case(b"connection") {
        for option in value.split(|byte| *byte == b',') {
            let option = option.trim_ascii();
            if option.eq_ignore_ascii_case(b"close") {
                framing.connection = Connection::Close;
            } else if option.eq_ignore_ascii_case(b"keep-alive")
                && !matches!(framing.connection, Connection::Close)
            {
                framing.connection = Connection::KeepAlive;
            } else {
                // Other options name hop-by-hop headers.
            }
        }
    } else {
        // Other headers are the caller's to read.
    }
    Ok(())
}

/// A decimal number of one or more digits, None past u64.
fn decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    let mut value = 0_u64;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
    }
    Some(value)
}

/// Any bytes as a response, fed whole and a piece at a time, the piece
/// sizes taken from the input: both read the same body and end alike.
#[cfg(fuzzing)]
pub fn fuzz_response(input: &[u8]) {
    let Some((&seed, message)) = input.split_first() else {
        return;
    };
    let whole = tests::run(message, seed & 1 == 1, message.len().max(1));
    let piece = usize::from(seed >> 1) % 17 + 1;
    let split = tests::run(message, seed & 1 == 1, piece);
    assert_eq!(whole, split);
    let bytes = tests::run(message, seed & 1 == 1, 1);
    assert_eq!(whole, bytes);
}

#[cfg(any(test, fuzzing))]
mod tests {
    use super::{Error, Event, Response};
    use alloc::vec::Vec;

    /// What a response gave: status, body, the bytes consumed, whether
    /// the connection may be reused, or the error.
    #[derive(Debug, PartialEq)]
    pub struct Outcome {
        pub status: u16,
        pub body: Vec<u8>,
        pub used: usize,
        pub reusable: bool,
    }

    /// Feeds message in pieces of piece bytes, as reads would bring it,
    /// up to the response's end or the message's, which is then the
    /// connection's close.
    pub fn run(message: &[u8], head_request: bool, piece: usize) -> Result<Outcome, Error> {
        let mut parser = Response::new(head_request);
        let mut body = Vec::new();
        let mut used = 0;
        for read in message.chunks(piece) {
            let mut at = 0;
            while let Some(rest) = read.get(at..) {
                let (taken, event) = parser.feed(rest)?;
                assert!(taken <= rest.len());
                at += taken;
                used += taken;
                match event {
                    Event::Need => {
                        assert_eq!(at, read.len());
                        break;
                    }
                    Event::Head => assert!(parser.status() >= 200 || parser.status() == 101),
                    Event::Body(bytes) => {
                        assert!(!bytes.is_empty());
                        // Borrowed from the read, not copied.
                        let start = rest.get(taken - bytes.len()..).map(<[u8]>::as_ptr);
                        assert_eq!(start, Some(bytes.as_ptr()));
                        body.extend_from_slice(bytes);
                    }
                    Event::End => {
                        return Ok(Outcome {
                            status: parser.status(),
                            body,
                            used,
                            reusable: parser.reusable(),
                        });
                    }
                }
            }
        }
        parser.eof()?;
        Ok(Outcome {
            status: parser.status(),
            body,
            used,
            reusable: parser.reusable(),
        })
    }

    /// run at every split in two and a byte at a time: each gives what the
    /// whole message gives.
    #[cfg(test)]
    fn every_split(message: &[u8], head_request: bool) -> Result<Outcome, Error> {
        let whole = run(message, head_request, message.len().max(1));
        assert_eq!(run(message, head_request, 1), whole);
        for cut in 1..message.len() {
            let mut parser = Response::new(head_request);
            let (first, second) = message.split_at(cut);
            let mut outcome = Ok(Vec::new());
            let mut done = false;
            for read in [first, second] {
                let mut at = 0;
                while !done && outcome.is_ok() {
                    match parser.feed(&read[at..]) {
                        Ok((taken, event)) => {
                            at += taken;
                            match event {
                                Event::Need => break,
                                Event::Head => {}
                                Event::Body(bytes) => {
                                    if let Ok(body) = &mut outcome {
                                        body.extend_from_slice(bytes);
                                    }
                                }
                                Event::End => done = true,
                            }
                        }
                        Err(error) => outcome = Err(error),
                    }
                }
            }
            if outcome.is_ok() && !done {
                if let Err(error) = parser.eof() {
                    outcome = Err(error);
                }
            }
            match (&whole, outcome) {
                (Ok(whole), Ok(body)) => assert_eq!(whole.body, body, "cut at {cut}"),
                (Err(whole), Err(error)) => assert_eq!(*whole, error, "cut at {cut}"),
                (whole, outcome) => panic!("cut at {cut}: {whole:?} against {outcome:?}"),
            }
        }
        whole
    }

    #[cfg(test)]
    mod cases {
        use super::super::{
            Body, Error, Event, HEAD_MAX, HEADERS_MAX, Response, chunk, chunk_head, last_chunk,
            request,
        };
        use super::{every_split, run};
        use alloc::vec::Vec;
        use test::Bencher;

        fn ok(message: &[u8], head_request: bool) -> super::Outcome {
            every_split(message, head_request).unwrap()
        }

        fn fails(message: &[u8], error: Error) {
            assert_eq!(every_split(message, false), Err(error));
        }

        #[test]
        fn writes_a_request() {
            let mut out = Vec::new();
            let headers: [(&[u8], &[u8]); 2] =
                [(b"Accept", b"*/*"), (b"User-Agent", b"rr\tx \x80")];
            request(
                &mut out,
                b"GET",
                b"/a?b=c",
                b"example.com",
                &headers,
                &Body::None,
            )
            .unwrap();
            assert_eq!(
                out,
                b"GET /a?b=c HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\
                  User-Agent: rr\tx \x80\r\n\r\n"
            );
            out.clear();
            request(
                &mut out,
                b"POST",
                b"/",
                b"h:8080",
                &[],
                &Body::Length(1234567890),
            )
            .unwrap();
            assert_eq!(
                out,
                b"POST / HTTP/1.1\r\nHost: h:8080\r\nContent-Length: 1234567890\r\n\r\n"
            );
            out.clear();
            request(&mut out, b"PUT", b"*", b"h", &[], &Body::Length(0)).unwrap();
            assert!(out.ends_with(b"Content-Length: 0\r\n\r\n"));
            out.clear();
            request(&mut out, b"PUT", b"/", b"h", &[], &Body::Chunked).unwrap();
            chunk(&mut out, b"hello");
            chunk(&mut out, b"");
            chunk_head(&mut out, 0x1a2b);
            last_chunk(&mut out);
            assert!(
                out.ends_with(b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n1a2b\r\n0\r\n\r\n")
            );
        }

        /// CR, LF and NUL anywhere, and the framing headers, are refused
        /// and out is left as it was.
        #[test]
        fn refuses_header_injection() {
            let mut out = b"kept".to_vec();
            let bad: [&[u8]; 4] = [b"a\rb", b"a\nb", b"a\0b", b""];
            for field in bad {
                let valued: [(&[u8], &[u8]); 1] = [(b"X", field)];
                let value_error = request(&mut out, b"GET", b"/", b"h", &valued, &Body::None);
                // An empty value is a value; the others are not.
                assert_eq!(value_error.is_ok(), field.is_empty());
                out.truncate(4);
                let headers: [(&[u8], &[u8]); 1] = [(field, b"v")];
                for result in [
                    request(&mut out, field, b"/", b"h", &[], &Body::None),
                    request(&mut out, b"GET", field, b"h", &[], &Body::None),
                    request(&mut out, b"GET", b"/", field, &[], &Body::None),
                    request(&mut out, b"GET", b"/", b"h", &headers, &Body::None),
                ] {
                    assert_eq!(result, Err(Error::Field));
                }
                assert_eq!(out, b"kept");
            }
            for name in [
                &b"Host"[..],
                b"content-length",
                b"Transfer-Encoding",
                b"A B",
                b"A:",
            ] {
                let headers: [(&[u8], &[u8]); 1] = [(name, b"1")];
                let result = request(&mut out, b"GET", b"/", b"h", &headers, &Body::None);
                assert_eq!(result, Err(Error::Field));
            }
            assert_eq!(
                request(&mut out, b"GET", b"/ HTTP/1.1", b"h", &[], &Body::None),
                Err(Error::Field)
            );
            assert_eq!(out, b"kept");
        }

        #[test]
        fn content_length() {
            let message = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A:  b c \r\n\r\nhelloNEXT";
            let outcome = ok(message, false);
            assert_eq!(outcome.status, 200);
            assert_eq!(outcome.body, b"hello");
            assert_eq!(outcome.used, message.len() - 4);
            assert!(outcome.reusable);
            let mut parser = Response::new(false);
            let (taken, event) = parser.feed(message).unwrap();
            assert_eq!(event, Event::Head);
            assert_eq!(parser.header(b"x-a"), Some(&b"b c"[..]));
            assert_eq!(parser.header(b"content-length"), Some(&b"5"[..]));
            assert_eq!(
                parser.header_at(0),
                Some((&b"Content-Length"[..], &b"5"[..]))
            );
            assert_eq!(parser.header_count(), 2);
            assert_eq!(parser.length(), Some(5));
            assert_eq!(parser.header(b"none"), None);
            assert_eq!(
                parser.feed(&message[taken..]).unwrap(),
                (5, Event::Body(b"hello"))
            );
            assert_eq!(parser.feed(b"NEXT").unwrap(), (0, Event::End));
            assert_eq!(parser.feed(b"NEXT").unwrap(), (0, Event::End));
            assert_eq!(parser.eof(), Ok(()));
            // A list of one length, and the same header twice, are one.
            ok(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\nContent-Length: 3\r\n\r\nabc",
                false,
            );
            let empty = ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false);
            assert!(empty.body.is_empty());
            assert!(empty.reusable);
        }

        #[test]
        fn chunked() {
            let message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n\
                5\r\nhello\r\n\
                0B ; name=value;x=\"q d\"\r\n, world!!!!\r\n\
                1\n.\n\
                0;last\r\nTrailer-A: 1\r\nTrailer-B: 2\r\n\r\nNEXT";
            let outcome = ok(message, false);
            assert_eq!(outcome.body, b"hello, world!!!!.");
            assert_eq!(outcome.used, message.len() - 4);
            assert!(outcome.reusable);
            let bare = ok(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n0\r\n\r\n",
                false,
            );
            assert!(bare.body.is_empty());
        }

        #[test]
        fn until_close() {
            let message = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nall of it";
            let outcome = ok(message, false);
            assert_eq!(outcome.body, b"all of it");
            assert_eq!(outcome.used, message.len());
            assert!(!outcome.reusable);
            // HTTP/1.0 without a length, and a close after nothing.
            let old = ok(b"HTTP/1.0 200 OK\r\n\r\n", false);
            assert!(old.body.is_empty());
            let mut parser = Response::new(false);
            assert_eq!(parser.feed(b"").unwrap(), (0, Event::Need));
            assert_eq!(parser.eof(), Err(Error::Closed));
        }

        /// 1xx heads are skipped; HEAD, 204 and 304 end at the head; 101
        /// ends with the connection given to the other protocol.
        #[test]
        fn without_body() {
            let message =
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n\
                HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
            let outcome = ok(message, false);
            assert_eq!(outcome.status, 200);
            assert_eq!(outcome.body, b"hi");
            let mut parser = Response::new(false);
            let (taken, event) = parser.feed(message).unwrap();
            assert_eq!((taken, event), (message.len() - 2, Event::Head));
            assert_eq!(parser.header(b"link"), None);
            assert_eq!(parser.header_count(), 1);
            let head =
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\nX";
            let headed = ok(head, true);
            assert_eq!(headed.used, head.len() - 1);
            assert!(headed.body.is_empty());
            for empty in [
                &b"HTTP/1.1 204 No Content\r\nContent-Length: 7\r\n\r\n"[..],
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 7\r\n\r\n",
            ] {
                let nothing = ok(empty, false);
                assert!(nothing.body.is_empty());
                assert!(nothing.reusable);
            }
            let switch = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nframes";
            let upgrade = ok(switch, false);
            assert_eq!(upgrade.status, 101);
            assert_eq!(upgrade.used, switch.len() - 6);
            assert!(!upgrade.reusable);
        }

        #[test]
        fn keep_alive() {
            for (message, reusable) in [
                (&b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..], true),
                (b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", false),
                (b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive, Close\r\nContent-Length: 0\r\n\r\n", false),
                (b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", false),
                (b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n", true),
                (b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n", false),
            ] {
                assert_eq!(ok(message, false).reusable, reusable);
            }
        }

        /// Two responses on one connection, fed from one buffer.
        #[test]
        fn pipelined() {
            let message =
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 404 Not Found\r\n\
                Transfer-Encoding: chunked\r\n\r\n1\r\nb\r\n0\r\n\r\n";
            let mut parser = Response::new(false);
            let mut at = 0;
            let mut statuses = Vec::new();
            let mut body = Vec::new();
            loop {
                let (taken, event) = parser.feed(&message[at..]).unwrap();
                at += taken;
                match event {
                    Event::Need => break,
                    Event::Head => statuses.push(parser.status()),
                    Event::Body(bytes) => body.extend_from_slice(bytes),
                    Event::End => {
                        assert!(parser.reusable());
                        parser.restart(false);
                    }
                }
            }
            assert_eq!(statuses, [200, 404]);
            assert_eq!(body, b"ab");
            assert_eq!(at, message.len());
        }

        #[test]
        fn strict_heads() {
            for (message, error) in [
                (&b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"[..], Error::Length),
                (b"HTTP/1.1 200 OK\r\nContent-Length: 1, 2\r\n\r\n", Error::Length),
                (b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", Error::Length),
                (b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n", Error::Length),
                (b"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n", Error::Length),
                (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n", Error::Coding),
                (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", Error::Coding),
                (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", Error::Coding),
                (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", Error::Coding),
                (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ,\r\n\r\n", Error::Coding),
                (b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", Error::Coding),
                (b"HTTP/1.1 200 OK\r\nA: 1\r\n folded\r\n\r\n", Error::Fold),
                (b"HTTP/1.1 200 OK\r\nA: 1\0\r\n\r\n", Error::Header),
                (b"HTTP/1.1 200 OK\r\nA: 1\r2\r\n\r\n", Error::Header),
                (b"HTTP/1.1 200 OK\r\nA : 1\r\n\r\n", Error::Header),
                (b"HTTP/1.1 200 OK\r\n: 1\r\n\r\n", Error::Header),
                (b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n", Error::Header),
                (b"HTTP/1.1 200 O\0K\r\n\r\n", Error::Status),
                (b"HTTP/2 200 OK\r\n\r\n", Error::Status),
                (b"HTTP/1.1 20 OK\r\n\r\n", Error::Status),
                (b"HTTP/1.1 600 OK\r\n\r\n", Error::Status),
                (b"HTTP/1.1  200 OK\r\n\r\n", Error::Status),
                (b"HTTP/1.1 200OK\r\n\r\n", Error::Status),
            ] {
                fails(message, error);
            }
            // The status line may end at the code.
            assert_eq!(ok(b"HTTP/1.1 200\r\n\r\n", false).status, 200);
            assert_eq!(ok(b"HTTP/1.1 200 \r\n\r\n", false).status, 200);
        }

        #[test]
        fn strict_chunks() {
            let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
            for (chunks, error) in [
                (&b"x\r\n"[..], Error::Chunk),
                (b"\r\n", Error::Chunk),
                (b";a\r\n", Error::Chunk),
                (b"1 x\r\n", Error::Chunk),
                (b"1\rx\n", Error::Chunk),
                (b"1;a\0\r\n", Error::Chunk),
                (b"1\r\nab\r\n", Error::Chunk),
                (b"1\r\na\rb", Error::Chunk),
                (b"10000000000000000\r\n", Error::Chunk),
                (b"0\r\nA: 1\0\r\n\r\n", Error::Header),
                (b"0\r\nA: 1\rB\r\n\r\n", Error::Header),
                (b"0\r\n\rx", Error::Chunk),
                (b"5\r\nabc", Error::Truncated),
                (b"0\r\nA: 1\r\n", Error::Truncated),
            ] {
                // rr: escape(copy): the message is built on a copy of its head.
                let mut message = head.to_vec();
                message.extend_from_slice(chunks);
                fails(&message, error);
            }
            // rr: escape(copy): the message is built on a copy of its head.
            let mut long = head.to_vec();
            long.extend_from_slice(b"1;");
            long.resize(long.len() + 5000, b'a');
            fails(&long, Error::Chunk);
            // rr: escape(copy): the message is built on a copy of its head.
            let mut big = head.to_vec();
            big.extend_from_slice(b"ffffffffffffffff\r\nab");
            assert_eq!(every_split(&big, false), Err(Error::Truncated));
            fails(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab",
                Error::Truncated,
            );
            fails(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n",
                Error::Truncated,
            );
        }

        /// The heads together stop at HEAD_MAX bytes and HEADERS_MAX
        /// fields; just under both is read.
        #[test]
        fn limits() {
            let head = b"HTTP/1.1 200 OK\r\n";
            // rr: escape(copy): the message is built on a copy of its head.
            let mut message = head.to_vec();
            let filler = HEAD_MAX - head.len() - b"A: \r\n\r\n".len();
            message.extend_from_slice(b"A: ");
            message.resize(message.len() + filler, b'a');
            message.extend_from_slice(b"\r\n\r\n");
            assert_eq!(message.len(), HEAD_MAX);
            assert!(run(&message, false, 1000).is_ok());
            message.insert(head.len() + 3, b'a');
            assert_eq!(run(&message, false, 1000), Err(Error::TooLarge));
            assert_eq!(run(&message, false, 1), Err(Error::TooLarge));
            // rr: escape(copy): the message is built on a copy of its head.
            let mut many = head.to_vec();
            for _ in 0..HEADERS_MAX {
                many.extend_from_slice(b"A: 1\r\n");
            }
            many.extend_from_slice(b"\r\n");
            assert!(run(&many, false, 7).is_ok());
            many.truncate(many.len() - 2);
            many.extend_from_slice(b"A: 1\r\n\r\n");
            assert_eq!(run(&many, false, 7), Err(Error::TooLarge));
            // Interim heads count toward the limit.
            let mut interim = Vec::new();
            while interim.len() < HEAD_MAX {
                interim.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
            }
            interim.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
            assert_eq!(run(&interim, false, 4096), Err(Error::TooLarge));
            // So do trailers.
            let mut trailers =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
            while trailers.len() < HEAD_MAX + 16 {
                trailers.extend_from_slice(b"T: 1\r\n");
            }
            trailers.extend_from_slice(b"\r\n");
            assert_eq!(run(&trailers, false, 4096), Err(Error::TooLarge));
        }

        /// An error stays until restart, which readies the next response.
        #[test]
        fn error_sticks() {
            let mut parser = Response::new(false);
            assert_eq!(parser.feed(b"HTTP/9"), Ok((6, Event::Need)));
            assert_eq!(parser.feed(b"\r\n"), Err(Error::Status));
            assert_eq!(parser.feed(b"HTTP/1.1 200 OK\r\n"), Err(Error::Status));
            assert_eq!(parser.eof(), Err(Error::Status));
            parser.restart(false);
            assert_eq!(
                parser.feed(b"HTTP/1.1 204 OK\r\n\r\n"),
                Ok((19, Event::Head))
            );
            assert_eq!(parser.feed(b""), Ok((0, Event::End)));
        }

        /// A 1 MiB chunked body in 8000-byte chunks, fed in 16 KiB reads
        /// as a socket would bring them; the body is never copied.
        #[bench]
        fn chunked_1m(b: &mut Bencher) {
            let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            let data = [0x61_u8; 8000];
            let mut left = 1 << 20;
            while left > 0 {
                let size = left.min(data.len());
                chunk(&mut message, &data[..size]);
                left -= size;
            }
            last_chunk(&mut message);
            let mut parser = Response::new(false);
            b.iter(|| {
                parser.restart(false);
                let mut total = 0;
                for read in message.chunks(16 * 1024) {
                    let mut at = 0;
                    while at < read.len() {
                        let (taken, event) = parser.feed(&read[at..]).unwrap();
                        at += taken;
                        if let Event::Body(bytes) = event {
                            total += bytes.len();
                        }
                    }
                }
                assert_eq!(parser.feed(b"").unwrap(), (0, Event::End));
                assert_eq!(total, 1 << 20);
            });
        }
    }
}
