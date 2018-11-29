import urllib.request
import json
import time


PWNED_EMAIL_API_URL = "https://haveibeenpwned.com/api/v2/breachedaccount/{0}?truncateResponse=true"


class InvalidEmail(Exception):
    pass


class too_many_attemps(Exception):
    pass


class checkEmail(object):
    """
    Check if mail listed in a given file have been compromised,
    And right the output in a file, following the pattern:
    email: [websites_url_source_of_the_leak]
    """
    input_file = "mail_list.txt"
    output_file = "compromised_email.txt"
    compromised_email = []

    def get_breaches_infos_from_api(self, email):
        url = PWNED_EMAIL_API_URL.format(email)
        req = urllib.request.Request(url,
                                     data=None,
                                     headers={
                                         'User-Agent': 'Mozilla/5.0 \
                                         (Macintosh; Intel Mac OS X 10_9_3) \
                                         AppleWebKit/537.36 (KHTML, like Gecko) \
                                         Chrome/35.0.1916.47 Safari/537.36'
                                     })
        try:
            resp = urllib.request.urlopen(req)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 400:
                raise InvalidEmail("Email address does not appear to be a valid email")
            elif e.code == 429:
                print("Too many attemps\nTrying again in 1 sec")
                time.sleep(1)
                return get_breaches_infos_on_email(email)
            return []

    def adapt_data_for_compromised_email(self):
        f = open(self.output_file, 'w')
        for email, websites in self.compromised_email:
            websites = ' | '.join(websites)
            f.write("{0}: [{1}]".format(email, websites))
        f.close()

    @staticmethod
    def run(self):
        f = open(self.input_file, 'r')
        for email in f:
            email = email.strip()
            result = get_breaches_infos_from_api(email)
            if result:
                self.compromised_email.append([email, result])
            time.sleep(.3500)
        f.close()
        self.write_compromised_email_in_file()


if __name__ in '__main__':
    checkEmail.run()
