import argparse, sys
from threading import BoundedSemaphore
from httpinsert.request import manual_request, raw_request
from httpinsert.insertion_points import find_insertion_points
from httpinsert import Headers
import requests
from http.cookiejar import DefaultCookiePolicy
import logging


class ParseHeaders(argparse.Action):
    """
    Parsing headers from cli arguments
    """

    def __call__(self, parser, namespace, values, option_string=None):
        d = getattr(namespace, self.dest) or Headers()
        if values:
            for item in values:
                split_items = item.split(":", 1)
                key = split_items[0].strip()
                value = split_items[1]
                d[key] = value.strip()
        setattr(namespace, self.dest, d)


VERBOSE_LEVEL = 15
def verbose(self, message, *args, **kwargs):
    if self.isEnabledFor(VERBOSE_LEVEL):
        self._log(VERBOSE_LEVEL, message, args, **kwargs)

class Options:
    """
    Adds multiple options for how the scanner should behave
    """

    def __init__(self):
        self.args = None
        self.req = None
        self.proxies={}
        self.get_args()
        self.lock = BoundedSemaphore(self.args.threads)

        # Setting up logger
        logging.addLevelName(VERBOSE_LEVEL, "VERBOSE")
        logging.Logger.verbose = verbose

        self.logger = logging.getLogger("DiffCDLogger")
        log_level = logging.INFO
        if self.args.debug:
            log_level = logging.DEBUG
        elif self.args.verbose:
            log_level = VERBOSE_LEVEL
        self.logger.setLevel(log_level)
        console_handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def get_args(self):
        parser = argparse.ArgumentParser(
            prog="diffcd",
            description="A Content Discovery tool for finding more interesting/hidden content on web applications",
        )
        parser.add_argument(
            "--wordlist",
            "-w",
            required=True,
            help="Specify wordlist to scan for filenames (extensions will be appended to all filenames)",
        )

        parser.add_argument(
            "--extensions",
            "-e",
            default=[""],
            nargs="+",
        )

        target_parser = parser.add_argument_group("target")
        target_parser_2 = target_parser.add_mutually_exclusive_group(required=True)
        target_parser_2.add_argument("--url", "-u")
        target_parser_2.add_argument("--request", "--req", "-r", help="Specify a file containing a raw request for scanning")

        request_parser = parser.add_argument_group("request")
        request_parser.add_argument("--method", "-m", default="GET")
        request_parser.add_argument("--header", nargs="+", action=ParseHeaders, default={})
        request_parser.add_argument("--body", "-b", default="", help="Specify content to be in the body of the request")
        request_parser.add_argument("--threads", "-t", default=10, type=int)
        request_parser.add_argument("--proxy", "-p")
        request_parser.add_argument("--https", "--tls", action="store_true", default=False)
        request_parser.add_argument("--verify", default=False, action="store_true", help="Verify SSL certificates")
        request_parser.add_argument(
            "--allow-redirects", "-ar", default=False, action="store_true", help="Specify if requests should follow redirects"
        )
        # Waiting for urllib3 to release http 2 support
        # request_parser.add_argument("--version", default="HTTP/2")

        verbosity_parser = parser.add_argument_group("verbosisty")
        verbosity_parser.add_argument("--verbose", "-v", action="store_true", default=False)
        verbosity_parser.add_argument("--debug", "-d", action="store_true", default=False)

        scan_parser = parser.add_argument_group("scan")
        scan_parser.add_argument(
            "--sleep",
            "-ss",
            "-s",
            default=0,
            type=int,
            help="Determines how long (ms) the scanner should sleep between each request during scan",
        )
        scan_parser.add_argument(
            "--calibration-sleep",
            "-cs",
            default=0,
            type=int,
            help="Determines how long (ms) the scanner should sleep between each request while calibrating",
        )
        scan_parser.add_argument("--timeout", type=float, default=8.0, help="Determines the timeout duration (s) for each request")
        scan_parser.add_argument(
            "--ignore-errors",
            "-ie",
            default=False,
            action="store_true",
            help="Ignore errors if any errors occurs during calibration",
        )

        analyzer_parser = parser.add_argument_group("analyzer")
        analyzer_parser.add_argument(
            "--no-analyze-all",
            action="store_false",
            default=True,
            help="Make analyzer skip analyzing the body if the content length is static",
        )
        analyzer_parser.add_argument(
            "--num-calibrations", type=int, default=10, help="Specify how many requests should be sent during calibration"
        )
        analyzer_parser.add_argument(
            "--num-verifications", type=int, default=6, help="Specify how many times an endpoint should be verified/re-tested"
        )

        self.args = parser.parse_args()
        self.set_args()

    def parse_request(self):
        """
        Reads a request from file and parses it to be used when sending requests.
        """
        with open(self.args.request, "rb") as f:
            data = f.read()
        scheme="http"
        if self.args.https or (self.args.url and self.args.url.startswith("https")):
            scheme="https"
        return raw_request(scheme,data)

    def set_args(self):
        """
        Used for processing misc options.
        """
        if self.args.proxy:
            self.proxies["http"]=self.args.proxy
            self.proxies["https"]=self.args.proxy
        if self.args.request:
            self.req=self.parse_request()
        else:
            scheme="http"
            if self.args.https is True or (self.args.url and self.args.url.startswith("https")):
                scheme="https"
            host = self.args.url.split("/")[2]
            path = "/"+"/".join(self.args.url.split("/")[3:]).split("?")[0]
            query = ""
            if "?" in self.args.url:
                query = "?"+"?".join(self.args.url.split("?")[1:])
            url = f"{scheme}://{host}{path}{query}"
            self.req = manual_request(scheme,self.args.method, host,url,"HTTP/1.1",self.args.header,self.args.body.encode())
        insertion_points = find_insertion_points(self.req,location="Manual")
        insertion_points = insertion_points or [find_insertion_points(self.req,location="Path")[-1]]

        self.insertion_points = insertion_points
        self.req.sessions=[]
        for i in range(self.args.threads):
            session = requests.Session()
            session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[])) # Prevent cookies from being set
            self.req.sessions.append(session)
