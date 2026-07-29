from diffcd.options import Options
from diffcd.output import Reporter, parse_headers
from httpdiff import Baseline, Response

from threading import Thread, BoundedSemaphore, Lock
import queue
import random
import time
import string

from urllib.parse import urlparse
import requests
import re


class DiffCD:
    def __init__(self, options):
        self.count=0
        self.stop=False
        self.options=options
        self.baselines={}
        self.calibration_lock = Lock()
        self.calibrating={}
        self.queue = queue.Queue()

        # Counter of requests actually sent (for progress logging).
        self.sent = 0
        self.sent_lock = Lock()

        # Reporter handles all finding output (stdout / file); logs stay on stderr.
        self.reporter = Reporter(
            fmt=self.options.args.output_format,
            color=not self.options.args.no_color,
            output=self.options.args.output,
            logger=self.options.logger,
        )

    def find_key(self, insertion_point,payload,ext,pd):
        directory=""
        if "/" in payload:
            directory = "/".join(payload.split("/")[:-1])
        if "/" in ext:
            ext="/"
        if pd is True:
            directory = "/".join(directory.split("/")[:2])+"/PD"
            return insertion_point+directory

        key = insertion_point + directory + "/" + ext
        return key

    def send(self, insertion):
        insertions = [insertion]
        time.sleep(self.options.args.sleep/1000)
        resp, response_time,error = self.options.req.send(debug=self.options.args.debug,insertions=insertions,allow_redirects=self.options.args.allow_redirects,timeout=self.options.args.timeout,verify=self.options.args.verify,proxies=self.options.proxies)
        if error:
            self.options.logger.debug(f"Error occured while sending request: {error}")
            error = str(type(error)).encode()

        # Track progress and emit an occasional liveness line on stderr.
        with self.sent_lock:
            self.sent += 1
            sent = self.sent
        if sent % 1000 == 0:
            self.options.logger.info(f"Progress: {sent} requests sent, {self.reporter.count} finding(s)")

        return Response(resp),response_time,error

    def build_result(self, insertion, resp, response_time, error, sections):
        """Assemble a rich, JSON-serializable record describing a confirmed hit."""
        changes = {}
        for s in sections:
            changes[s["section"]] = changes.get(s["section"], 0) + len(s["diffs"])

        url = insertion.full_section
        if isinstance(url, bytes):
            url = url.decode("latin-1", errors="replace")

        result = {
            "url": url,
            "status_code": None,
            "reason": None,
            "content_length": None,
            "response_time_ms": round(response_time, 1) if response_time is not None else None,
            "location": None,
            "redirected": False,
            "redirect_status": None,
            "changed_sections": [s["section"] for s in sections],
            "changes": changes,
            "error": None,
        }

        if error:
            result["error"] = error.decode("latin-1", errors="replace") if isinstance(error, bytes) else str(error)

        if resp is not None and not getattr(resp, "none", False):
            result["status_code"] = resp.status_code
            reason = resp.reason
            result["reason"] = reason.decode("latin-1", errors="replace") if isinstance(reason, bytes) else reason
            result["content_length"] = len(resp.content)

            headers = parse_headers(resp.headers)
            for k, v in headers.items():
                if k.lower() == "location":
                    result["location"] = v
                    break

            if getattr(resp, "history", None):
                result["redirected"] = True
                try:
                    result["redirect_status"] = resp.history[0].status_code
                except Exception:
                    pass

        return result

    def calibrate_baseline(self,insertion_point,payload,ext,key):
        character_set = list(set(payload)) or string.ascii_lowercase+string.ascii_uppercase
        if self.stop is True:
            return None
        baseline = self.baselines.get(key,Baseline())
        baseline.verbose = self.options.args.verbose
        baseline.analyze_all = not self.options.args.no_analyze_all
        self.options.logger.verbose(f"Calibrating baseline for key '{key}'")

        for i in range(self.options.args.num_calibrations):
            random_value = ''.join(random.choices(character_set, k=random.randint(3,50)))
            insertion = insertion_point.insert(random_value+ext,self.options.req,default_encoding=not self.options.args.disable_encoding)
            sleep_time = max(0,self.options.args.calibration_sleep/1000 - self.options.args.sleep/1000)
            time.sleep(sleep_time)
            resp, response_time,error = self.send(insertion)
            if error and self.options.args.ignore_errors is False:
                self.stop=True
                self.options.logger.critical(f"Error occured during calibration, stopping scan as ignore-errors is not set: {error}")
                return
            baseline.add_response(resp,response_time,error,payload=random_value)

        sleep_time = self.options.args.calibration_sleep/1000 or self.options.args.sleep/1000
        time.sleep(sleep_time)
        resp, response_time,error = self.send(insertion)
        if error and self.options.args.ignore_errors is False:
            self.stop=True
            self.options.logger.critical(f"Error occured during calibration, stopping scan as ignore-errors is not set: {error}")
            return
        baseline.add_response(resp,response_time,error,payload=random_value)
        self.options.logger.verbose(f"Done calibrating for key '{key}'")
        return baseline



    def check_endpoint(self,insertion_point,payload,ext,checks=0,pd=False,key=None):
        insertion1 = insertion_point.insert(payload+ext,self.options.req,default_encoding=not self.options.args.disable_encoding)
        time.sleep(self.options.args.sleep/1000)
        if self.stop is True:
            return
        resp, response_time,error = self.send(insertion1)
        if key is None:
            # The key is derived once per job and passed on to every re-check below.
            # Re-deriving it mid-job would let a PD job fall back onto the shared
            # directory baseline and fight with it over calibration.
            key = self.find_key(str(insertion_point),payload,ext,pd)
        if self.baselines.get(key) is None:
            self.calibration_lock.acquire()
            if self.baselines.get(key) is None:
                self.baselines[key] = self.calibrate_baseline(insertion_point,payload,ext,key)
            self.calibration_lock.release()
            if self.stop is True:
                return None

        sections = list(self.baselines[key].find_diffs(resp,response_time,error))

        character_set = list(set(payload)) or string.ascii_lowercase+string.ascii_uppercase
        if len(sections) > 0:
            random_value = ''.join(random.choices(character_set, k=random.randint(3,50)))
            insertion2 = insertion_point.insert(random_value+ext,self.options.req,default_encoding=not self.options.args.disable_encoding) # {randomstring}{ext}
            time.sleep(self.options.args.sleep/1000)
            resp2, response_time2,error2 = self.send(insertion2)

            sections2 = list(self.baselines[key].find_diffs(resp2,response_time2,error2))

            if sections == sections2:
                self.baselines[key].add_response(resp2,response_time2,error2,payload=random_value) 


                if self.calibrating.get(key) is True:
                    self.calibration_lock.acquire() # Wait for calibration to finish
                    self.calibration_lock.release()
                    return self.check_endpoint(insertion_point,payload,ext,pd=pd,key=key) # checks is reset since we don't know whether the incorrect baseline affected the results
                self.calibration_lock.acquire()
                self.calibrating[key] = True
                self.calibrate_baseline(insertion_point,payload,ext,key)
                self.calibration_lock.release()
                if self.stop is True:
                    return None
                self.calibrating[key] = False
                self.count=0
                return self.check_endpoint(insertion_point,payload,ext,pd=pd,key=key)

            insertion3 = insertion_point.insert(''.join(random.choices(character_set, k=random.randint(3,50)))+payload+ext,self.options.req,default_encoding=not self.options.args.disable_encoding) # {randomstring}{previouspayload}{ext}
            time.sleep(self.options.args.sleep/1000)
            resp3, response_time3,error3 = self.send(insertion3)

            sections3 = list(self.baselines[key].find_diffs(resp3,response_time3,error3))
            if sections == sections3:
                self.count=0
                return

            insertion4 = insertion_point.insert(payload+''.join(random.choices(character_set, k=random.randint(3,50)))+ext,self.options.req,default_encoding=not self.options.args.disable_encoding) # {previouspayload}{randomstring}{ext}
            time.sleep(self.options.args.sleep/1000)
            resp4, response_time4,error4 = self.send(insertion4)

            sections4 = list(self.baselines[key].find_diffs(resp4,response_time4,error4))
            if sections == sections4:
                self.count=0
                return 

            if checks >= self.options.args.num_verifications:
                self.count+=1
                if self.count > 100:
                    self.stop=True
                    # TODO: Do some more testing here to see if there are any other options than just stopping the scan
                    self.options.logger.critical(f"All of the last 100 payloads gave a valid result, something is wrong, stopping the scan")
                    return
                result = self.build_result(insertion1, resp, response_time, error, sections)
                self.reporter.report(result)
            else:
                return self.check_endpoint(insertion_point,payload,ext,checks=checks+1,pd=pd,key=key)


    def separate_payload(self,word):
        if not word: # The payload is an empty string
            return "", ""

        if word[-1] == "/": # Scanning for directories
            return word[:-1],"/"

        if "." in word.split("/")[-1]: # Some extension is found
            ext = "."+word.split("/")[-1].split(".")[-1]
            return ext.join(word.split(ext)[:-1]), ext

        return word, "" # No extension discovered

    def worker(self):
        while True:
            args = self.queue.get()
            if args is None:
                break
            try:
                self.check_endpoint(*args)
            except Exception:
                pass
            finally:
                self.queue.task_done()


    def scan(self):
        jobs = []
        for _ in range(self.options.args.threads):
            job = Thread(target=self.worker,daemon=True)
            job.start()
            jobs.append(job)
        with open(self.options.args.wordlist,"r") as f:
            wordlist = f.read().splitlines()

        self.options.logger.info(
            f"Starting scan: {len(wordlist)} words x {len(self.options.args.extensions)} extension(s), "
            f"{self.options.args.threads} threads, output={self.options.args.output_format}"
        )

        for insertion_point in self.options.insertion_points:
            for ext in self.options.args.extensions:
                if ext.lower() == "none":
                    ext=""
                ext2=""
                for word in wordlist:
                    if self.stop is True:
                        return
                    if not ext:
                        word,ext2 = self.separate_payload(word)
                    if ext == "/" or ext2 == "/":
                        # Let's look for /FUZZ/gibberish as well as /FUZZ/!
                        random_string = ''.join(random.choices(string.ascii_lowercase+string.ascii_uppercase, k=random.randint(3,50)))
                        self.queue.put((insertion_point,word,"/"+random_string,0,True))
                    self.queue.put((insertion_point,word,ext or ext2))
        for _ in range(self.options.args.threads):
            self.queue.put(None)


        for job in jobs:
            job.join()

        self.reporter.summary()
        self.reporter.close()


def main():
    options = Options()
    diffcd = DiffCD(options)
    diffcd.scan()

if __name__ == "__main__":
    main()
