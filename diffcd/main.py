from diffcd.options import Options
from httpdiff import Baseline, Response

from threading import Thread, BoundedSemaphore, Lock
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
        self.job_lock = BoundedSemaphore(self.options.args.threads)
        self.calibration_lock = Lock()
        self.calibrating={}

    def find_key(self, insertion_point,payload,ext):
        directory=""
        if "/" in payload:
            directory = "/".join(payload.split("/")[:-1])
        key = insertion_point + directory + ext
        return key

    def send(self, insertion):
        insertions = [insertion]
        time.sleep(self.options.args.sleep/1000)
        resp, response_time,error = self.options.req.send(debug=self.options.args.debug,insertions=insertions,allow_redirects=self.options.args.allow_redirects,timeout=self.options.args.timeout,verify=self.options.args.verify,proxies=self.options.proxies)
        if error:
            self.options.logger.debug(f"Error occured while sending request: {error}")
            error = str(type(error)).encode()
        return Response(resp),response_time,error

    def calibrate_baseline(self,insertion_point,payload,ext):
        character_set = list(set(payload)) or string.ascii_lowercase+string.ascii_uppercase
        if self.stop is True:
            return None
        key = self.find_key(str(insertion_point),payload,ext)
        baseline = self.baselines.get(key,Baseline())
        baseline.verbose = self.options.args.verbose
        baseline.analyze_all = not self.options.args.no_analyze_all
        self.options.logger.verbose(f"Calibrating baseline for key '{key}'")

        for i in range(self.options.args.num_calibrations):
            random_value = ''.join(random.choices(character_set, k=random.randint(10,20)))
            insertion = insertion_point.insert(random_value+ext,self.options.req)
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
        baseline.add_response(resp,response_time,error,payload=random_value)
        self.options.logger.verbose(f"Done calibrating for key '{key}'")
        return baseline



    def check_endpoint(self,insertion_point,payload,ext,checks=0):
        insertion1 = insertion_point.insert(payload+ext,self.options.req)
        time.sleep(self.options.args.sleep/1000)
        if self.stop is True:
            self.job_lock.release()
            return
        resp, response_time,error = self.send(insertion1)
        key = self.find_key(str(insertion_point),payload,ext)
        if self.baselines.get(key) is None:
            self.calibration_lock.acquire()
            if self.baselines.get(key) is None:
                self.baselines[key] = self.calibrate_baseline(insertion_point,payload,ext)
            self.calibration_lock.release()
            if self.stop is True:
                self.job_lock.release()
                return None

        sections = list(self.baselines[key].find_diffs(resp,response_time,error))

        character_set = list(set(payload)) or string.ascii_lowercase+string.ascii_uppercase
        if len(sections) > 0:
            insertion2 = insertion_point.insert(''.join(random.choices(character_set, k=random.randint(10,20)))+ext,self.options.req) # {randomstring}{ext}
            time.sleep(self.options.args.sleep/1000)
            resp2, response_time2,error2 = self.send(insertion2)

            sections2 = list(self.baselines[key].find_diffs(resp2,response_time2,error2))

            if sections == sections2:
                self.baselines[key].add_response(resp2,response_time2,error2)


                if self.calibrating.get(key) is True:
                    self.calibration_lock.acquire() # Wait for calibration to finish
                    self.calibration_lock.release()
                    return self.check_endpoint(insertion_point,payload,ext)
                self.calibration_lock.acquire()
                self.calibrating[key] = True
                self.calibrate_baseline(insertion_point,payload,ext)
                self.calibration_lock.release()
                if self.stop is True:
                    self.job_lock.release()
                    return None
                self.calibrating[key] = False
                self.count=0
                return self.check_endpoint(insertion_point,payload,ext)

            insertion3 = insertion_point.insert(''.join(random.choices(character_set, k=random.randint(10,20)))+payload+ext,self.options.req) # {randomstring}{previouspayload}{ext}
            time.sleep(self.options.args.sleep/1000)
            resp3, response_time3,error3 = self.send(insertion3)

            sections3 = list(self.baselines[key].find_diffs(resp3,response_time3,error3))
            if sections == sections3:
                self.job_lock.release()
                self.count=0
                return

            insertion4 = insertion_point.insert(payload+''.join(random.choices(character_set, k=random.randint(10,20)))+ext,self.options.req) # {previouspayload}{randomstring}{ext}
            time.sleep(self.options.args.sleep/1000)
            resp4, response_time4,error4 = self.send(insertion4)

            sections4 = list(self.baselines[key].find_diffs(resp4,response_time4,error4))
            if sections == sections4:
                self.job_lock.release()
                self.count=0
                return 

            insertion5 = insertion_point.insert(payload,self.options.req)
            if checks >= self.options.args.num_verifications:
                self.count+=1
                if self.count > 100:
                    self.stop=True
                    # TODO: Do some more testing here to see if there are any other options than just stopping the scan
                    self.options.logger.critical(f"All of the last 100 payloads gave a valid result, something is wrong, stopping the scan")
                    self.job_lock.release()
                    return
                sections_diffs_len = {}
                for i in sections:
                    if i["section"] not in sections_diffs_len.keys():
                        sections_diffs_len[i["section"]] = 0
                    sections_diffs_len[i["section"]]+=len(i["diffs"])
                self.options.logger.info(f"{insertion1.full_section} - {sections_diffs_len}")
            else:
                return self.check_endpoint(insertion_point,payload,ext,checks=checks+1)
        self.job_lock.release()


    def separate_payload(self,word):
        if not word: # The payload is an empty string
            return "", ""

        if word[-1] == "/": # Scanning for directories
            return word[:-1],"/"

        if "." in word.split("/")[-1]: # Some extension is found
            ext = "."+word.split("/")[-1].split(".")[-1]
            return ext.join(word.split(ext)[:-1]), ext

        return word, "" # No extension discovered

    def scan(self):
        with open(self.options.args.wordlist,"r") as f:
            wordlist = f.read().splitlines()

        jobs = []
        for insertion_point in self.options.insertion_points:
            for ext in self.options.args.extensions:
                if ext.lower() == "none":
                    ext=""
                ext2=""
                for word in wordlist:
                    self.job_lock.acquire()
                    if self.stop is True:
                        return
                    if not ext:
                        word,ext2 = self.separate_payload(word)
                    job = Thread(target=self.check_endpoint,args=(insertion_point,word,ext or ext2,))
                    jobs.append(job)
                    job.start()


                for job in jobs:
                    job.join()
                jobs = []


def main():
    options = Options()
    diffcd = DiffCD(options)
    diffcd.scan()




if __name__ == "__main__":
    main()
