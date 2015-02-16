#!/usr/bin/env python

## Open Sourced by - Newsman App www.newsmanapp.com
## (c) 2013 Newsman App
## https://github.com/Newsman/MailToJson

import sys, urllib2, email, re, csv, StringIO, base64, json
import datetime
import ssdeep
import hashlib
from optparse import OptionParser

ERROR_NOUSER = 67
ERROR_PERM_DENIED = 77
ERROR_TEMP_FAIL = 75

# url regex from https://github.com/shiva-spampot/shiva/blob/master/analyzer/core/shivamailparser.py
url_re = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')

# regular expresion from https://github.com/django/django/blob/master/django/core/validators.py
email_re = re.compile(
    r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
    # quoted-string, see also http://tools.ietf.org/html/rfc2822#section-3.2.5
    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"'
    r')@((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)$)'  # domain
    r'|\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$', re.IGNORECASE)

email_extract_re = re.compile("<(([.0-9a-z_+-=]+)@(([0-9a-z-]+\.)+[0-9a-z]{2,9}))>", re.M|re.S|re.I)
#filename_re = re.compile("filename=\"(.*?)\"", re.I|re.S)
filename_re = re.compile("filename=\"(.+)\"|filename=([^;\n\r\"\']+)", re.I|re.S)

class MailJson:
    def __init__(self, content):
        self.data = {}
        self.encoding = "utf-8" # output encoding
        self.setContent(content)

    def setEncoding(self, encoding):
        self.encoding = encoding

    def setContent(self, content):
        self.content = content

    def _fixEncodedSubject(subject):
        subject = "%s" % subject
        subject = subject.strip()

        if len(subject) < 2:
            # empty string or not encoded string ?
            return subject
        if subject.find("\n") == -1:
            # is on single line
            return subject
        if subject[0:2] != "=?":
            # not encoded
            return subject

        subject = subject.replace("\r", "")
        subject = begin_tab_re.sub("", subject)
        subject = begin_space_re.sub("", subject)
        lines = subject.split("\n")

        new_subject = ""
        for l in lines:
            new_subject = "%s%s" % (new_subject, l)
            if l[-1] == "=":
                new_subject = "%s\n " % new_subject

        return new_subject

    def _extract_email(self, s):
        ret = email_extract_re.findall(s)
        if len(ret) < 1:
            return None
        else:
            return ret[0][0]

    def _decode_headers(self, v):
        if type(v) is not list:
            v = [ v ]

        ret = []
        for h in v:
            h = email.Header.decode_header(h)
            h_ret = []
            for h_decoded in h:
                hv = h_decoded[0]
                h_encoding = h_decoded[1]
                if h_encoding is None:
                    h_encoding = "ascii"
                else:
                    h_encoding = h_encoding.lower()

                hv = unicode(hv, h_encoding).strip().strip("\t")


                h_ret.append(hv.encode(self.encoding))

            ret.append(" ".join(h_ret))

        return ret

    def _get_md5sum(self, file):
        m = hashlib.md5()
        m.update(file)
        return m.hexdigest()

    def _parse_recipients(self, v):
        if v is None:
            return None

        v = v.replace("\n", " ").replace("\r", " ")
        s = StringIO.StringIO(v)
        c = csv.reader(s)
        row = c.next()

        ret = []
        for entry in row:
            entry = entry.strip()
            if email_re.match(entry):
                e = entry
                entry = ""
            else:
                e = self._extract_email(entry)
                entry = entry.replace("<%s>" % e, "")
                entry = entry.strip()

            ret.append({"name": entry, "email": e})

        return ret

    def _parse_links(self, body):
        links = set([group[0] for group in url_re.findall(body)])
        mylist = list(set(links))

        return mylist

    def _parse_date(self, v):
        if v is None:
            return datetime.datetime.now()

        tt = email.utils.parsedate_tz(v)

        if tt is None:
            return datetime.datetime.now()

        timestamp = email.utils.mktime_tz(tt)
        date = datetime.datetime.fromtimestamp(timestamp)
        return date

    def _get_ssdeep(self, content):
        random = "Bacon ipsum dolor amet spare ribs tri-tip alcatra, prosciutto turkey beef ball tip hamburger capicola kielbasa meatball. Kielbasa biltong tenderloin short loin. Prosciutto pork chop ground round sirloin chicken. Short ribs tail pastrami, strip steak chicken doner jerky brisket tenderloin. Ball tip andouille venison, kevin pork loin kielbasa beef. Shank strip steak ball tip biltong bresaola, prosciutto picanha. Bacon porchetta doner chicken, rump jerky flank kielbasa turkey ball tip tongue alcatra pork chop short loin kevin. Shoulder pancetta andouille ham hock biltong jerky brisket corned beef kevin. Flank porchetta ham chicken turducken beef ham hock strip steak pork pastrami meatball t-bone boudin corned beef chuck. Doner cow rump pancetta ham hock tri-tip. Pancetta swine short ribs beef ribs jowl. T-bone pork salami, drumstick doner filet mignon hamburger short ribs picanha tenderloin. Beef ribs cupim capicola, venison shoulder fatback frankfurter meatball pork belly. Jowl swine biltong chuck filet mignon, bresaola sirloin beef kevin. Tongue ribeye chuck, strip steak chicken tail tenderloin sausage porchetta. Turkey filet mignon venison, pork belly hamburger beef ribs ball tip prosciutto doner t-bone pork."
        
        if len(content) < 150:
            data = content + " " + random
        else:
            data = content

        return ssdeep.hash(data)

    def _get_content_charset(self, part, failobj = None):
        """Return the charset parameter of the Content-Type header.

        The returned string is always coerced to lower case.  If there is no
        Content-Type header, or if that header has no charset parameter,
        failobj is returned.
        """
        missing = object()
        charset = part.get_param('charset', missing)
        if charset is missing:
            return failobj
        if isinstance(charset, tuple):
            # RFC 2231 encoded, so decode it, and it better end up as ascii.
            pcharset = charset[0] or 'us-ascii'
            try:
                # LookupError will be raised if the charset isn't known to
                # Python.  UnicodeError will be raised if the encoded text
                # contains a character not in the charset.
                charset = unicode(charset[2], pcharset).encode('us-ascii')
            except (LookupError, UnicodeError):
                charset = charset[2]
        # charset character must be in us-ascii range
        try:
            if isinstance(charset, unicode):
                charset = charset.encode("us-ascii")
            charset = unicode(charset, 'us-ascii').encode('us-ascii')
        except UnicodeError:
            return failobj
        # RFC 2046, $4.1.2 says charsets are not case sensitive
        return charset.lower()

    def parse(self):
        self.msg = email.message_from_string(self.content)

        # raw headers
        headers = {}
        for k in self.msg.keys():
            k = k.lower()
            v = self.msg.get_all(k)
            v = self._decode_headers(v)

            if len(v) == 1:
                headers[k] = v[0]
            else:
                headers[k] = v

        self.data["headers"] = headers
        self.data["timestamp"] = self._parse_date(headers.get("date", None))
        self.data["subject"] = headers.get("subject", None)
        self.data["to"] = self._parse_recipients(headers.get("to", None))
        self.data["from"] = self._parse_recipients(headers.get("from", None))
        self.data["cc"] = self._parse_recipients(headers.get("cc", None))

        attachments = []
        parts = []
        links = []
        for part in self.msg.walk():
            if part.is_multipart():
                continue

            content_disposition = part.get("Content-Disposition", None)
            if content_disposition:
                # we have attachment
                r = filename_re.findall(content_disposition)
                if r:
                    # this returns a list with tuple with 2 values, 1 per match group
                    filename = sorted(r[0])[1]
                else:
                    filename = "undefined"

                payload = part.get_payload(decode = True)
                a = { "filename": filename, "content":  base64.b64encode(payload), "content_type": part.get_content_type(), "md5sum": self._get_md5sum(payload) }
                attachments.append(a)
            else:
                content = unicode(part.get_payload(decode = 1), self._get_content_charset(part, "utf-8"), "ignore").encode(self.encoding)
                links.extend(self._parse_links(content))
                p = {"content_type": part.get_content_type(), "content": content, "ssdeep": self._get_ssdeep(content) }
                parts.append(p)

        urls = []
        for url in list(set(links)):
            urls.append({"url": url})

        self.data["attachments"] = attachments
        self.data["parts"] = parts
        self.data["links"] = urls
        self.data["encoding"] = self.encoding

    def getData(self):
        return self.data

if __name__ == "__main__":
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-u", "--url", dest = "url", action = "store", help = "the url where to post the mail data as json")
    
    opt, args = parser.parse_args()

    if not opt.url:
        print parser.format_help()
        sys.exit(1)
    
    content = sys.stdin.read()
    
    try:
        mj = MailJson(content)
        mj.parse()
        data = mj.getData()
    
        headers = {"Content-Type": "application/json; charset=%s" % data.get("encoding")}
        req = urllib2.Request(opt.url, json.dumps(data, encoding = data.get("encoding")), headers)
        resp = urllib2.urlopen(req)
        ret = resp.read()
    
        print "Parsed Mail Data sent to: %s\n" % opt.url
    except Exception, inst:
        print "ERR: %s" % inst
        sys.exit(ERROR_TEMP_FAIL)
