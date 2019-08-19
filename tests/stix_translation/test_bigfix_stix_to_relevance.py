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
from stix_shifter.stix_translation.src.modules.bigfix.query_constructor import RelevanceQueryStringPatternTranslator
from unittest.mock import patch
import unittest
import re

translation = stix_translation.StixTranslation()


relevance_map_dict = {
  "property_format_string_mapping":
  {
    "generic_format_string" : "{mapped_field} of it as lowercase {comparator} {value} as lowercase",
    "time_range_format_string" : "{mapped_field} of it is {comparator_1} {start_value} as time {comparator} {mapped_field} of it is {comparator_2} {end_value} as time",
    "match_operation_format_string" : "exist {comparator}({value}) of {mapped_field} of it"
  },
  "default_property":
  {
        "=" : "generic_format_string",
        "!=" : "generic_format_string",
        "contains" : "generic_format_string",
        "matches" : "match_operation_format_string"
  },
  "qualifie":
  {
    "file" :
    {
      "mapped_field" : "modification time",
      "format_pattern" : "time_range_format_string"
    },
    "process" :
    {
      "mapped_field" : "start time",
      "format_pattern" : "time_range_format_string"
    }
  }
}


def _remove_timestamp_from_query(queries):
    pattern = '\"\d{2}\s[a-zA-Z]{3}\s\d{4}\s(\d{2}\:){2}(\d{2})\s(\+|\-){1}\d{4}\"'
    if isinstance(queries, list):
        return [re.sub(pattern, "", query) for query in queries]
    elif isinstance(queries, str):
        return re.sub(pattern, "", queries)


class TestStixToRelevance(unittest.TestCase):

    def _test_query_assertions(self, query, queries):
        self.assertIsInstance(query, dict)
        self.assertIsInstance(query['queries'], list)
        for index, each_query in enumerate(query.get('queries'), start=0):
            self.assertEqual(each_query, queries[index])

    maxDiff = None

    def test_one_obser_eq_operator_file(self):
        stix_pattern = "[file:name = 'jffs.conf'] START t'2013-01-10T08:43:10.003Z' STOP t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string = "jffs.conf" as string)) AND (modification time of it is greater than or equal to "10 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_ne_operator_file(self):
        stix_pattern =  "[file:name != 'securetty'] START t'2013-01-10T08:43:10.003Z' STOP t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as lowercase != "securetty" as lowercase)) AND (modification time of it is greater than or equal to "10 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_in_operator_file(self):
        stix_pattern =  "[file:name IN ('freevxfs.conf','masthead.afxm')] START t'2013-01-10T08:43:10.003Z' STOP t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose ((((name of it as string = "freevxfs.conf" as string) OR (name of it as string = "masthead.afxm" as string))) AND (modification time of it is greater than or equal to "10 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_like_operator_file(self):
        stix_pattern =  "[file:name LIKE  '.bash%'] START t'2013-01-10T08:43:10.003Z' STOP t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string contains regex"(.bash.*$)" )) AND (modification time of it is greater than or equal to "10 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_match_operator_file(self):
        stix_pattern = "[file:name MATCHES  '^.bash.*'] START t'2013-01-10T08:43:10.003Z' STOP t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((exist matches(regex"(^.bash.*)") of (name of it as string))) AND (modification time of it is greater than or equal to "10 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_combined_comparision_eq_operator_file(self):
        stix_pattern =  "[file:name =  'cramfs.conf' AND file:hashes.'SHA-256'  =  'faced6f3282d6c81243cb68aa662783bdf95ba12e2acce4fe5d178fc8c0b1cd3'] START t'2013-01-10T08:43:10.003Z' STOP t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((sha256 of it as string = "faced6f3282d6c81243cb68aa662783bdf95ba12e2acce4fe5d178fc8c0b1cd3" as string) AND (name of it as string = "cramfs.conf" as string)) AND (modification time of it is greater than or equal to "10 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_combined_comparision_ne_operator_file(self):
        stix_pattern = "[file:name != 'systemd-udevd' AND file:parent_directory_ref.path = '/root' OR file:hashes.'SHA-256' != '0c68730046ca864602b103e1828236011ba401731b07ed87efefb9d14648f44f']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((sha256 of it as string != "0c68730046ca864602b103e1828236011ba401731b07ed87efefb9d14648f44f" as string) OR (name of it as string != "systemd-udevd" as string)) AND (modification time of it is greater than or equal to "16 Aug 2019 14:43:25 +0000" as time AND modification time of it is less than or equal to "16 Aug 2019 14:48:25 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_combined_comparision_in_operator_file(self):
        stix_pattern = "[file:name IN ('original-ks.cfg') AND file:parent_directory_ref.path = '/root' OR file:hashes.'SHA-256' IN ('71d3364323e818a505b4deeede97fc3d0ba0e3c71f4b43f63d9c584bea946bd1')]"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose ((((sha256 of it as string = "71d3364323e818a505b4deeede97fc3d0ba0e3c71f4b43f63d9c584bea946bd1" as string)) OR ((name of it as string = "original-ks.cfg" as string))) AND (modification time of it is greater than or equal to "16 Aug 2019 14:44:34 +0000" as time AND modification time of it is less than or equal to "16 Aug 2019 14:49:34 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_combined_comparision_like_operator_file(self):
        stix_pattern = "[file:parent_directory_ref.path = '/root' AND file:name LIKE 'bash']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string contains "bash" as string)) AND (modification time of it is greater than or equal to "19 Aug 2019 14:49:44 +0000" as time AND modification time of it is less than or equal to "19 Aug 2019 14:54:44 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_combined_comparision_operator_file(self):
        stix_pattern = "[file:name MATCHES '^hfs.*' AND file:parent_directory_ref.path = '/root' AND file:hashes.'SHA-256' MATCHES '63786314a518f10eabd93102bcba9e6e5da48e753de4f606d4d31111c223743b']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((exist matches(regex"(63786314a518f10eabd93102bcba9e6e5da48e753de4f606d4d31111c223743b)") of (sha256 of it as string)) AND (exist matches(regex"(^hfs.*)") of (name of it as string))) AND (modification time of it is greater than or equal to "19 Aug 2019 14:34:31 +0000" as time AND modification time of it is less than or equal to "19 Aug 2019 14:39:31 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_two_combinedObser_operator_file(self):
        stix_pattern = "([file:name LIKE 'init' AND file:parent_directory_ref.path = '/etc'] AND [file:name MATCHES 'free.*' AND file:parent_directory_ref.path = '/root']) START t'2013-01-01T08:43:10.003Z' STOP t'2019-07-25T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =   ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string contains "init" as string)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/etc")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((exist matches(regex"(free.*)") of (name of it as string))) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_three_combinedObser_operator_file(self):
        stix_pattern = "([file:name =  'gshadow' AND file:parent_directory_ref.path = '/etc'] AND [file:name MATCHES 'init.*' AND file:parent_directory_ref.path = '/etc'] OR [file:name IN ('gshadow','grub.conf') AND file:parent_directory_ref.path = '/etc']) START t'2013-01-01T08:43:10.003Z' STOP t'2019-07-25T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as lowercase = "gshadow" as lowercase)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/etc")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((exist matches(regex"(init.*)") of (name of it as string))) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/etc")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose ((((name of it as lowercase = "gshadow" as lowercase) OR (name of it as lowercase = "grub.conf" as lowercase))) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/etc")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_four_combinedObser_operator_file(self):
        stix_pattern =  "([file:name = 'gshadow' AND file:parent_directory_ref.path = '/etc'] AND [file:name = '.bashrc' AND file:parent_directory_ref.path = '/root'] OR [file:name IN ('hfs.conf','.bashrc','.bash_history')] AND [file:parent_directory_ref.path = '/root'] AND [file:hashes.'md5' = '3ca8190245489eb84f646d63ad6ef49f' AND file:name = 'freevxfs.conf']) START t'2013-01-01T08:43:10.003Z' STOP t'2019-07-25T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as lowercase = "gshadow" as lowercase)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/etc")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string = ".bashrc" as string)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose ((((name of it as string = "hfs.conf" as string) OR (name of it as string = ".bashrc" as string) OR (name of it as string = ".bash_history" as string))) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose ((modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string = "freevxfs.conf" as string) AND (md5 of it as string = "3ca8190245489eb84f646d63ad6ef49f" as string)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_five_combinedObser_operator_file(self):
        stix_pattern = "([file:name =  'DIR_COLORS.256color' AND file:parent_directory_ref.path = '/etc'] AND [file:name =  '.bashrc' AND file:parent_directory_ref.path = '/root'] OR [process:name = 'rpciod'] AND [file:parent_directory_ref.path = '/root'] AND [file:hashes.'md5' = '3ca8190245489eb84f646d63ad6ef49f']) START t'2013-01-01T08:43:10.003Z' STOP t'2019-07-25T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =   ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string = "DIR_COLORS.256color" as string)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/etc")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string = ".bashrc" as string)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as lowercase = "rpciod" as lowercase)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND creation time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time) else (start time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND start time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose ((modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((md5 of it as string = "3ca8190245489eb84f646d63ad6ef49f" as string)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

# PROCESS

    def test_one_obser_eq_operator_process(self):
        stix_pattern =  "[process:name = 'rpciod']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as lowercase = "rpciod" as lowercase)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "16 Aug 2019 14:57:34 +0000" as time AND creation time of it is less than or equal to "16 Aug 2019 15:02:34 +0000" as time) else (start time of it is greater than or equal to "16 Aug 2019 14:57:34 +0000" as time AND start time of it is less than or equal to "16 Aug 2019 15:02:34 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_ne_operator_process(self):
        stix_pattern = "[process:name != 'systemd-journald']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as string != "systemd-journald" as string)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "16 Aug 2019 14:58:36 +0000" as time AND creation time of it is less than or equal to "16 Aug 2019 15:03:36 +0000" as time) else (start time of it is greater than or equal to "16 Aug 2019 14:58:36 +0000" as time AND start time of it is less than or equal to "16 Aug 2019 15:03:36 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_in_operator_process(self):
        stix_pattern = "[process:name IN ('systemd-journald','systemd-udevd')]"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose ((((name of it as string = "systemd-journald" as string) OR (name of it as string = "systemd-udevd" as string))) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "16 Aug 2019 14:59:19 +0000" as time AND creation time of it is less than or equal to "16 Aug 2019 15:04:19 +0000" as time) else (start time of it is greater than or equal to "16 Aug 2019 14:59:19 +0000" as time AND start time of it is less than or equal to "16 Aug 2019 15:04:19 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_like_operator_process(self):
        stix_pattern = "[process:name LIKE 'rpciod']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as string contains "rpciod" as string)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "19 Aug 2019 14:30:31 +0000" as time AND creation time of it is less than or equal to "19 Aug 2019 14:35:31 +0000" as time) else (start time of it is greater than or equal to "19 Aug 2019 14:30:31 +0000" as time AND start time of it is less than or equal to "19 Aug 2019 14:35:31 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_match_operator_process(self):
        stix_pattern = "[process:name MATCHES 'sys.*']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((exist matches(regex"(sys.*)") of (name of it as string))) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "19 Aug 2019 14:37:59 +0000" as time AND creation time of it is less than or equal to "19 Aug 2019 14:42:59 +0000" as time) else (start time of it is greater than or equal to "19 Aug 2019 14:37:59 +0000" as time AND start time of it is less than or equal to "19 Aug 2019 14:42:59 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_combinedObser_eq_operator_process(self):
        stix_pattern ="[process:name = 'ksoftirqd/0' OR file:hashes.'SHA-256' = '0c68730046ca864602b103e1828236011ba401731b07ed87efefb9d14648f44f']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((sha256 of image file of it as string = "0c68730046ca864602b103e1828236011ba401731b07ed87efefb9d14648f44f" as string) OR (name of it as string = "ksoftirqd/0" as string)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "16 Aug 2019 15:02:00 +0000" as time AND creation time of it is less than or equal to "16 Aug 2019 15:07:00 +0000" as time) else (start time of it is greater than or equal to "16 Aug 2019 15:02:00 +0000" as time AND start time of it is less than or equal to "16 Aug 2019 15:07:00 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_two_combinedObser_operator_process(self):
        stix_pattern = "([file:name =  'udf.conf'] AND [process:name = 'rpciod']) START t'2013-01-01T08:43:10.003Z' STOP t'2019-07-25T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries =  ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string = "udf.conf" as string)) AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as lowercase = "rpciod" as lowercase)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND creation time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time) else (start time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND start time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_three_combinedObser_operator_process(self):
        stix_pattern = "([process:name = 'systemd' AND file:hashes.'SHA-256' = '58da5f0548e6a0889855d29fc839199b6e9e81cb945713d9ada586fcf7baee5a'] AND [file:name LIKE 'rc.status' AND file:parent_directory_ref.path = '/etc'] OR [file:hashes.'SHA-256' = '97cc7eaf9e5b1e36eaf1f94bdb3b571e950aba38514f07d299f39719c9b91785' AND process:name = 'systemd-udevd']) START t'2012-04-10T08:43:10.003Z' STOP t'2020-04-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((sha256 of image file of it as string = "58da5f0548e6a0889855d29fc839199b6e9e81cb945713d9ada586fcf7baee5a" as string) AND (name of it as lowercase = "systemd" as lowercase)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "10 Apr 2012 08:43:10 +0000" as time AND creation time of it is less than or equal to "23 Apr 2020 10:43:10 +0000" as time) else (start time of it is greater than or equal to "10 Apr 2012 08:43:10 +0000" as time AND start time of it is less than or equal to "23 Apr 2020 10:43:10 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string contains "rc.status" as string)) AND (modification time of it is greater than or equal to "10 Apr 2012 08:43:10 +0000" as time AND modification time of it is less than or equal to "23 Apr 2020 10:43:10 +0000" as time)) of folder ("/etc")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>', '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as string = "systemd-udevd" as string) AND (sha256 of image file of it as string = "97cc7eaf9e5b1e36eaf1f94bdb3b571e950aba38514f07d299f39719c9b91785" as string)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or equal to "10 Apr 2012 08:43:10 +0000" as time AND creation time of it is less than or equal to "23 Apr 2020 10:43:10 +0000" as time) else (start time of it is greater than or equal to "10 Apr 2012 08:43:10 +0000" as time AND start time of it is less than or equal to "23 Apr 2020 10:43:10 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_eq_operator_network(self):
        stix_pattern = "[ipv4-addr:value = '192.168.36.10'] START t'2017-01-10T08:43:10.003Z' STOP t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])
        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>  ("Local Address", local address of it as string | "n/a", "Remote Address", remote address of it as string | "n/a", "Local port", local port of it | -1, "remote port", remote port of it | -1, "Process name", names of processes of it, pid of process of it,  "sha256", sha256 of image files of processes of it | "n/a",  "sha1", sha1 of image files of processes of it | "n/a",  "md5", md5 of image files of processes of it | "n/a",  pathname of image files of processes of it | "n/a",  (if (name of operating system as lowercase contains "win" as lowercase) then ("Creation time", (creation time of process of it - "01 Jan 1970 00:00:00 +0000" as time)/second) else ("Start time", (start time of process of it - "01 Jan 1970 00:00:00 +0000" as time)/second)), "TCP", tcp of it, "UDP", udp of it) of sockets whose (((local address of it as string = "192.168.36.10" as string OR remote address of it as string = "192.168.36.10" as string)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of process of it is greater than or equal to "10 Jan 2017 08:43:10 +0000" as time AND creation time of process of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time) else (start time of process of it is greater than or equal to "10 Jan 2017 08:43:10 +0000" as time AND start time of process of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time))) of network</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']
        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_ge_operator_network(self):
        stix_pattern = "[network-traffic:src_port = '443']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])
        queries = ['<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>  ("Local Address", local address of it as string | "n/a", "Remote Address", remote address of it as string | "n/a", "Local port", local port of it | -1, "remote port", remote port of it | -1, "Process name", names of processes of it, pid of process of it,  "sha256", sha256 of image files of processes of it | "n/a",  "sha1", sha1 of image files of processes of it | "n/a",  "md5", md5 of image files of processes of it | "n/a",  pathname of image files of processes of it | "n/a",  (if (name of operating system as lowercase contains "win" as lowercase) then ("Creation time", (creation time of process of it - "01 Jan 1970 00:00:00 +0000" as time)/second) else ("Start time", (start time of process of it - "01 Jan 1970 00:00:00 +0000" as time)/second)), "TCP", tcp of it, "UDP", udp of it) of sockets whose (((local port of it = 443 )) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation time of process of it is greater than or equal to "19 Aug 2019 18:01:46 +0000" as time AND creation time of process of it is less than or equal to "19 Aug 2019 18:06:46 +0000" as time) else (start time of process of it is greater than or equal to "19 Aug 2019 18:01:46 +0000" as time AND start time of process of it is less than or equal to "19 Aug 2019 18:06:46 +0000" as time))) of network</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']
        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    @patch('stix_shifter.stix_translation.src.modules.bigfix.query_constructor.RelevanceQueryStringPatternTranslator.__init__',autospec=True)
    def test_date_exception_handling(self,mock_init):
        mock_init.return_value = None
        qualifier = 'STARTt\'2018-04-10T08:43:10.003Z\'STOPt\'2018-04-23T10:43:10.003Z\''
        stix_obj = 'file'
        time_range = 5
        comparator_tuple = ('greater than or equal to', 'AND', 'less than or equal to')

        qualifier_string = RelevanceQueryStringPatternTranslator(pattern=None,data_model_mapper=None,result_limit=None,time_range=None)
        try:
            format_string=qualifier_string._parse_time_range(qualifier, stix_obj, relevance_map_dict, time_range,comparator_tuple)
        except Exception as ex:
            assert 'AttributeError' in str(type(ex))







