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
    input_file = "email_list.txt"
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
            print ("{0}: {1}".format(email, e.code))
            if e.code == 400:
                raise InvalidEmail("Email address does not appear to be a valid email")
            elif e.code == 429:
                print("Too many attemps\nTrying again in 1 sec")
                time.sleep(1)
                return self.get_breaches_infos_from_api(email)
            return []

    def write_compromised_email_in_file(self):
        f = open(self.output_file, 'w')
        for email, websites in self.compromised_email:
            websites = ' | '.join(websites)
            f.write("{0}: [{1}]\n".format(email, websites))
        f.close()

    def store_compromised_email_infos(self, email, result):
        if len(result) > 1:
            websites_names = []
            for infos in result:
                websites_names.append(infos['Name'])
        else:
            websites_names = [result[0]['Name']]
        self.compromised_email.append([email, websites_names])

    def run(self):
        f = open(self.input_file, 'r')
        for email in f:
            email = email.strip()
            result = self.get_breaches_infos_from_api(email)
            if result:
                self.store_compromised_email_infos(email, result)
            time.sleep(1)
        f.close()
        if len(self.compromised_email):
            self.write_compromised_email_in_file()
        else:
            print("No email from the given list is compromised\nGood job.")

if __name__ in '__main__':
    check_email = checkEmail()
    check_email.run()
