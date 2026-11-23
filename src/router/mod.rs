//! Cliente TR-064 para routers FRITZ!Box: SOAP sobre HTTP con autenticación
//! digest. Solo lectura (estado WAN, IP pública y hosts de la red).
//!
//! Las credenciales viven en memoria: este módulo no las guarda en disco.
//! TR-064 viene activado por defecto en la red local del FRITZ!Box.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use md5::{Digest, Md5};

const DEVICE_INFO_SVC: &str = "urn:dslforum-org:service:DeviceInfo:1";
const DEVICE_INFO_PATH: &str = "/upnp/control/deviceinfo";
const WAN_IP_SVC: &str = "urn:dslforum-org:service:WANIPConnection:1";
const WAN_IP_PATH: &str = "/upnp/control/wanipconnection1";
const WAN_COMMON_SVC: &str = "urn:dslforum-org:service:WANCommonInterfaceConfig:1";
const WAN_COMMON_PATH: &str = "/upnp/control/wancommonifconfig1";
const HOSTS_SVC: &str = "urn:dslforum-org:service:Hosts:1";
const HOSTS_PATH: &str = "/upnp/control/hosts";

#[derive(Clone, Debug, Default)]
pub struct RouterInfo {
    pub model: String,
    pub software: String,
    pub uptime_secs: u64,
}

#[derive(Clone, Debug, Default)]
pub struct WanStatus {
    pub external_ip: String,
    pub access_type: String,
    pub physical_link: String,
    pub up_mbps: f64,
    pub down_mbps: f64,
}

#[derive(Clone, Debug)]
pub struct RouterHost {
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub iface: String,
    pub active: bool,
}

/// Conexión a un TR-064 endpoint (p. ej. `http://192.168.178.1:49000`).
pub struct FritzBox {
    host: String,
    port: u16,
    prefix: String,
    user: String,
    password: String,
}

impl FritzBox {
    pub fn new(url: &str, user: &str, password: &str) -> anyhow::Result<Self> {
        let rest = url
            .trim()
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("La URL debe empezar por http:// (TR-064 va sin TLS)"))?;
        let (authority, prefix) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{p}").trim_end_matches('/').to_string()),
            None => (rest, String::new()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|e| anyhow::anyhow!("Puerto inválido en '{authority}': {e}"))?,
            ),
            None => (authority.to_string(), 49000),
        };
        if host.is_empty() {
            anyhow::bail!("URL sin host");
        }

        Ok(Self {
            host,
            port,
            prefix,
            user: user.to_string(),
            password: password.to_string(),
        })
    }

    pub fn info(&self) -> anyhow::Result<RouterInfo> {
        let xml = self.call(DEVICE_INFO_PATH, DEVICE_INFO_SVC, "GetInfo", "")?;
        Ok(RouterInfo {
            model: tag(&xml, "NewModelName"),
            software: tag(&xml, "NewSoftwareVersion"),
            uptime_secs: tag(&xml, "NewUpTime").trim().parse().unwrap_or(0),
        })
    }

    pub fn wan(&self) -> anyhow::Result<WanStatus> {
        let ip_xml = self.call(
            WAN_IP_PATH,
            WAN_IP_SVC,
            "GetExternalIPAddress",
            "",
        )?;
        let link = self.call(
            WAN_COMMON_PATH,
            WAN_COMMON_SVC,
            "GetCommonLinkProperties",
            "",
        )?;

        Ok(WanStatus {
            external_ip: tag(&ip_xml, "NewExternalIPAddress"),
            access_type: tag(&link, "NewWANAccessType"),
            physical_link: tag(&link, "NewPhysicalLinkStatus"),
            up_mbps: tag(&link, "NewLayer1UpstreamMaxBitRate")
                .trim()
                .parse::<f64>()
                .map(|bps| bps / 1_000_000.0)
                .unwrap_or(0.0),
            down_mbps: tag(&link, "NewLayer1DownstreamMaxBitRate")
                .trim()
                .parse::<f64>()
                .map(|bps| bps / 1_000_000.0)
                .unwrap_or(0.0),
        })
    }

    pub fn hosts(&self) -> anyhow::Result<Vec<RouterHost>> {
        let count_xml = self.call(
            HOSTS_PATH,
            HOSTS_SVC,
            "GetHostNumberOfEntries",
            "",
        )?;
        let count: usize = tag(&count_xml, "NewHostNumberOfEntries")
            .trim()
            .parse()
            .unwrap_or(0);

        let mut hosts = Vec::new();
        // Tope defensivo: una red doméstica no tiene miles de hosts.
        for i in 0..count.min(512) {
            let args = format!("<NewIndex>{i}</NewIndex>");
            let xml = match self.call(HOSTS_PATH, HOSTS_SVC, "GetGenericHostEntry", &args) {
                Ok(xml) => xml,
                Err(_) => continue, // índice sin datos
            };
            let ip = tag(&xml, "NewIPAddress");
            if ip.is_empty() {
                continue;
            }
            hosts.push(RouterHost {
                name: tag(&xml, "NewHostName"),
                ip,
                mac: tag(&xml, "NewMACAddress"),
                iface: tag(&xml, "NewInterfaceType"),
                active: tag(&xml, "NewActive").eq_ignore_ascii_case("1"),
            });
        }
        Ok(hosts)
    }

    /// Ejecuta una acción SOAP, reintentando con digest en el 401.
    fn call(&self, path: &str, service: &str, action: &str, args: &str) -> anyhow::Result<String> {
        let body = soap_envelope(service, action, args);
        let uri = format!("{}{}", self.prefix, path);

        let (status, headers, resp) =
            self.http_post(&uri, service, action, &body, None)?;

        if status == 401 {
            let challenge = headers
                .get("www-authenticate")
                .cloned()
                .unwrap_or_default();
            if !challenge.to_ascii_lowercase().contains("digest") {
                anyhow::bail!("El router exige autenticación no soportada: {challenge}");
            }
            let auth = digest_authorization(&challenge, "POST", &uri, &self.user, &self.password)
                .ok_or_else(|| anyhow::anyhow!("Desafío digest ilegible: {challenge}"))?;

            let (status, _, resp) = self.http_post(&uri, service, action, &body, Some(&auth))?;
            if status != 200 {
                anyhow::bail!(
                    "El router rechazó {action} (HTTP {status}). Revisa usuario y contraseña."
                );
            }
            return Ok(resp);
        }

        if status != 200 {
            anyhow::bail!("El router respondió HTTP {status} a {action}");
        }
        Ok(resp)
    }

    fn http_post(
        &self,
        uri: &str,
        service: &str,
        action: &str,
        body: &str,
        authorization: Option<&str>,
    ) -> anyhow::Result<(u16, HashMap<String, String>, String)> {
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("No se pudo resolver {}: {e}", self.host))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Sin dirección para {}", self.host))?;

        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .map_err(|e| anyhow::anyhow!("No se pudo conectar a {}:{}: {e}", self.host, self.port))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        let mut req = format!(
            "POST {uri} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Content-Type: text/xml; charset=\"utf-8\"\r\n\
             SOAPAction: \"{service}#{action}\"\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n",
            self.host,
            self.port,
            body.len()
        );
        if let Some(auth) = authorization {
            req.push_str(&format!("Authorization: {auth}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);

        stream.write_all(req.as_bytes())?;
        stream.flush()?;

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        parse_http_response(&raw)
    }
}

fn soap_envelope(service: &str, action: &str, args: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" \
         xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
         <s:Body><u:{action} xmlns:u=\"{service}\">{args}</u:{action}></s:Body></s:Envelope>"
    )
}

/// Separa estado, cabeceras y cuerpo de una respuesta HTTP/1.1.
fn parse_http_response(raw: &[u8]) -> anyhow::Result<(u16, HashMap<String, String>, String)> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("Respuesta HTTP truncada"))?;

    let head = String::from_utf8_lossy(&raw[..split]);
    let body = String::from_utf8_lossy(&raw[split + 4..]).to_string();

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("Línea de estado ilegible: {status_line}"))?;

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    Ok((status, headers, body))
}

/// Construye la cabecera `Authorization: Digest ...` para el desafío dado.
fn digest_authorization(
    challenge: &str,
    method: &str,
    uri: &str,
    user: &str,
    password: &str,
) -> Option<String> {
    let params = parse_challenge(challenge);
    let realm = params.get("realm")?;
    let nonce = params.get("nonce")?;
    let qop = params.get("qop").map(|q| q.split(',').any(|v| v.trim() == "auth"));
    let opaque = params.get("opaque");

    let ha1 = md5_hex(&format!("{user}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));

    let cnonce = format!("{:016x}", random_seed());
    let nc = "00000001";

    let response = if qop == Some(true) {
        md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"))
    } else {
        md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
    };

    let mut header = format!(
        "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\""
    );
    if qop == Some(true) {
        header.push_str(&format!(", qop=auth, nc={nc}, cnonce=\"{cnonce}\""));
    }
    if let Some(opaque) = opaque {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }
    Some(header)
}

/// Parsea `Digest realm="x", nonce="y", qop="auth"` a un mapa.
fn parse_challenge(challenge: &str) -> HashMap<String, String> {
    let body = challenge
        .trim()
        .strip_prefix("Digest ")
        .or_else(|| challenge.trim().strip_prefix("digest "))
        .unwrap_or(challenge);

    let mut out = HashMap::new();
    for part in body.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            out.insert(
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            );
        }
    }
    out
}

fn md5_hex(s: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(s.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn random_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ ((std::process::id() as u64) << 32)
}

/// Valor de la primera etiqueta `<name>...</name>` (sin namespaces).
fn tag(xml: &str, name: &str) -> String {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let Some(start) = xml.find(&open) else {
        return String::new();
    };
    let start = start + open.len();
    let Some(end) = xml[start..].find(&close) else {
        return String::new();
    };
    unescape(&xml[start..start + end])
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    fn read_request(stream: &TcpStream) -> String {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if let Some(v) = line.strip_prefix("Content-Length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            head.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).ok();
        head.push_str(&String::from_utf8_lossy(&body));
        head
    }

    fn field(req: &str, key: &str) -> String {
        req.split(&format!("{key}=\""))
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn digest_y_xml_contra_servidor_falso() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            // `wan()` hace dos acciones SOAP: cada una necesita su desafío.
            for round in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                let req = read_request(&s);
                assert!(req.contains("SOAPAction: \"urn:dslforum-org:service:"));
                assert!(!req.contains("Authorization:"));

                let nonce = format!("nonce{round}");
                let challenge = format!(
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"F!Box\", nonce=\"{nonce}\", qop=\"auth\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                s.write_all(challenge.as_bytes()).unwrap();
                drop(s);

                let (mut s, _) = listener.accept().unwrap();
                let req = read_request(&s);

                let cnonce = field(&req, "cnonce");
                let uri = field(&req, "uri");
                let expected = md5_hex(&format!(
                    "{}:{nonce}:00000001:{cnonce}:auth:{}",
                    md5_hex("admin:F!Box:secreto"),
                    md5_hex(&format!("POST:{uri}"))
                ));
                assert!(
                    req.contains(&format!("response=\"{expected}\"")),
                    "digest incorrecto en {uri}:\n{req}"
                );
                assert!(req.contains("username=\"admin\""));

                let body = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress><NewWANAccessType>DSL</NewWANAccessType><NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus><NewLayer1UpstreamMaxBitRate>40000000</NewLayer1UpstreamMaxBitRate><NewLayer1DownstreamMaxBitRate>100000000</NewLayer1DownstreamMaxBitRate></s:Body></s:Envelope>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                s.write_all(resp.as_bytes()).unwrap();
            }
        });

        let fb = FritzBox::new(&format!("http://{addr}"), "admin", "secreto").unwrap();
        let wan = fb.wan().unwrap();
        assert_eq!(wan.external_ip, "203.0.113.7");
        assert_eq!(wan.access_type, "DSL");
        assert_eq!(wan.down_mbps, 100.0);
        server.join().unwrap();
    }

    #[test]
    fn parsea_tags_y_entidades() {
        let xml = "<a><NewHostName>Casa &amp; Campo</NewHostName><NewIPAddress>192.168.1.5</NewIPAddress></a>";
        assert_eq!(tag(xml, "NewHostName"), "Casa & Campo");
        assert_eq!(tag(xml, "NewIPAddress"), "192.168.1.5");
        assert_eq!(tag(xml, "NewMACAddress"), "");
    }

    #[test]
    fn url_con_y_sin_puerto() {
        let a = FritzBox::new("http://192.168.178.1", "u", "p").unwrap();
        assert_eq!((a.host.as_str(), a.port), ("192.168.178.1", 49000));
        let b = FritzBox::new("http://fritz.box:8080/", "u", "p").unwrap();
        assert_eq!((b.host.as_str(), b.port), ("fritz.box", 8080));
        assert!(FritzBox::new("https://x", "u", "p").is_err());
    }
}
