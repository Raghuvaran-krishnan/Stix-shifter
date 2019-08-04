__author__ = ["Muralidhar K, Aarthi Pushkala Sen Rajamanickam, Raghuvaran Krishnan, Jayapradha Sivaperuman,"
              " Amalraj Arockiam, Subhash Chandra Bose N, Annish Prashanth Stevin Shankar, Karthick Rajagopal"]
__copyright__ = "Copyright 2019, IBM Client"
__credits__ = ["Muralidhar K, Aarthi Pushkala Sen Rajamanickam, Raghuvaran Krishnan, Jayapradha Sivaperuman,"
              " Amalraj Arockiam, Subhash Chandra Bose N, Annish Prashanth Stevin Shankar, Karthick Rajagopal"]
__license__ = ""
__version__ = "1.0.1"
__maintainer__ = "Muralidhar K"
__email__ = "Muralidhar K-ERS,HCLTech <murali_k@hcl.com>"
__status__ = "Development"

from stix_shifter.stix_translation import stix_translation
import unittest
import re

translation = stix_translation.StixTranslation()


def _remove_timestamp_from_query(queries):
    pattern = '\"\d{2}\s[a-zA-Z]{3}\s\d{4}\s(\d{2}\:){2}(\d{2})\s(\+|\-){1}\d{4}\"'
    if isinstance(queries, list):
        return [re.sub(pattern, "", query) for query in queries]
    elif isinstance(queries, str):
        return re.sub(pattern, "", queries)


class TestStixToRelevance(unittest.TestCase):
    maxDiff = None

    def _test_query_assertions(self, query, queries):
        self.assertIsInstance(query, dict)
        self.assertIsInstance(query['queries'], list)
        for index, each_query in enumerate(query.get('queries'), start=0):
            self.assertEqual(each_query, queries[index])

    def test_process_query(self):

        stix_pattern = "[process:name = 'node' AND file:hashes.'SHA-256' = " \
                       "'0c0017201b82e1d8613513dc80d1bf46320a957c393b6ca4fb7fa5c3b682c7e5']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])
        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
                   ' xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery>'
                   '<ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>'
                   '( "process", name of it | "n/a",  process id of it as string | "n/a",'
                   ' "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a",'
                   ' "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",'
                   '  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose'
                   ' ((sha256 of image file of it as'
                   ' lowercase = "0c0017201b82e1d8613513dc80d1bf46320a957c393b6ca4fb7fa5c3b682c7e5" as lowercase AND'
                   ' name of it as lowercase = "node" as lowercase) AND start time of it is greater than or equal to'
                   ' "30 Jul 2019 16:34:19 +0000" as time AND start time of it is less than or equal to'
                   ' "30 Jul 2019 16:39:19 +0000" as time)</QueryText><Target><CustomRelevance>true</CustomRelevance>'
                   '</Target></ClientQuery></BESAPI>']
        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)
