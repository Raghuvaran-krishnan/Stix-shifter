from stix_shifter.stix_translation import stix_translation
import unittest
import re

translation = stix_translation.StixTranslation()


def _remove_timestamp_from_query(queries):
    pattern = r'\"\d{2}\s[a-zA-Z]{3}\s\d{4}\s(\d{2}\:){2}(\d{2})\s(\+|\-){1}\d{4}\"'
    if isinstance(queries, list):
        return [re.sub(pattern, "", query) for query in queries]
    elif isinstance(queries, str):
        return re.sub(pattern, "", queries)


class TestStixToRelevance(unittest.TestCase):
    """
    class to perform unit test case bigfix translate query
    """

    def _test_query_assertions(self, query, queries):
        """
        to assert the each query in the list against expected result
        """
        self.assertIsInstance(query, dict)
        self.assertIsInstance(query['queries'], list)
        for index, each_query in enumerate(query.get('queries'), start=0):
            self.assertEqual(each_query, queries[index])

    maxDiff = None

    def test_one_obser_eq_operator_file(self):
        """
        to test single observation with '=' operator
        """
        stix_pattern = "[file:name = 'jffs.conf'] START t'2013-01-10T08:43:10.003Z' STOP t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = [
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", '
            'sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string = "jffs.conf" as string)) '
            'AND (modification time of it is greater than or equal to "10 Jan 2013 08:43:10 +0000" as time AND '
            'modification time of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time)) of folder ('
            '"/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_ne_operator_process(self):
        """
        to test single observation with '!=' operator
        """
        stix_pattern = "[process:name != 'systemd-journald']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = [
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | '
            '"n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", '
            'md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as string != "systemd-journald" '
            'as string)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation '
            'time of it is greater than or equal to "16 Aug 2019 14:58:36 +0000" as time AND creation time of it is '
            'less than or equal to "16 Aug 2019 15:03:36 +0000" as time) else (start time of it is greater than or '
            'equal to "16 Aug 2019 14:58:36 +0000" as time AND start time of it is less than or equal to "16 Aug 2019 '
            '15:03:36 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target'
            '></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_in_operator_file(self):
        """
        to test single observation with 'IN' operator
        """
        stix_pattern = "[file:name IN ('freevxfs.conf','masthead.afxm')] START t'2013-01-10T08:43:10.003Z' STOP " \
                       "t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = [
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", '
            'sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of files whose ((((name of it as string = "freevxfs.conf" as '
            'string) OR (name of it as string = "masthead.afxm" as string))) AND (modification time of it is greater '
            'than or equal to "10 Jan 2013 08:43:10 +0000" as time AND modification time of it is less than or equal '
            'to "23 Oct 2019 10:43:10 +0000" as time)) of folder ('
            '"/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_like_operator_network(self):
        """
        to test single observation with 'LIKE' operator
        """
        stix_pattern = "[ipv4-addr:value = '169.254.169.254' AND process:name LIKE  'Ec2Con%']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = [
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>  ("Local Address", local address of it as string | "n/a", '
            '"Remote Address", remote address of it as string | "n/a", "Local port", local port of it | -1, '
            '"remote port", remote port of it | -1, "Process name", names of processes of it, pid of process of it,  '
            '"sha256", sha256 of image files of processes of it | "n/a",  "sha1", sha1 of image files of processes of '
            'it | "n/a",  "md5", md5 of image files of processes of it | "n/a",  pathname of image files of processes '
            'of it | "n/a",  (if (name of operating system as lowercase contains "win" as lowercase) then ("Creation '
            'time", (creation time of process of it - "01 Jan 1970 00:00:00 +0000" as time)/second) else ("Start '
            'time", (start time of process of it - "01 Jan 1970 00:00:00 +0000" as time)/second)), "TCP", tcp of it, '
            '"UDP", udp of it) of sockets whose (((name of processes of it as string contains regex"(Ec2Con.*$)" ) '
            'AND (local address of it as string = "169.254.169.254" as string OR remote address of it as string = '
            '"169.254.169.254" as string)) AND (if (name of operating system as lowercase contains "win" as '
            'lowercase) then (creation time of process of it is greater than or equal to "23 Aug 2019 16:10:58 +0000" '
            'as time AND creation time of process of it is less than or equal to "23 Aug 2019 16:15:58 +0000" as '
            'time) else (start time of process of it is greater than or equal to "23 Aug 2019 16:10:58 +0000" as time '
            'AND start time of process of it is less than or equal to "23 Aug 2019 16:15:58 +0000" as time))) of '
            'network</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_obser_match_operator_file(self):
        """
        to test single observation with 'MATCH' operator
        """
        stix_pattern = "[file:name MATCHES  '^.bash.*'] START t'2013-01-10T08:43:10.003Z' STOP " \
                       "t'2019-10-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = [
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", '
            'sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of files whose (((exist matches(regex"(^.bash.*)") of (name of it '
            'as string))) AND (modification time of it is greater than or equal to "10 Jan 2013 08:43:10 +0000" as '
            'time AND modification time of it is less than or equal to "23 Oct 2019 10:43:10 +0000" as time)) of '
            'folder ("/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery'
            '></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_one_combined_comparision_like_operator_file(self):
        """
        to test single observation with 'LIKE' operator
        """
        stix_pattern = "[file:parent_directory_ref.path = '/root' AND file:name LIKE 'bash']"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = [
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", '
            'sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string contains "bash" as string)) '
            'AND (modification time of it is greater than or equal to "19 Aug 2019 14:49:44 +0000" as time AND '
            'modification time of it is less than or equal to "19 Aug 2019 14:54:44 +0000" as time)) of folder ('
            '"/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_two_combinedObser_operator_process(self):
        """
        to test 2 observation expression
        """
        stix_pattern = "([file:name =  'udf.conf'] AND [process:name = 'rpciod']) START t'2013-01-01T08:43:10.003Z' " \
                       "STOP t'2019-07-25T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = [
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", '
            'sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string = "udf.conf" as string)) '
            'AND (modification time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND '
            'modification time of it is less than or equal to "25 Jul 2019 10:43:10 +0000" as time)) of folder ('
            '"/root")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>',
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | '
            '"n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", '
            'md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as lowercase = "rpciod" as '
            'lowercase)) AND (if (name of operating system as lowercase contains "win" as lowercase) then (creation '
            'time of it is greater than or equal to "01 Jan 2013 08:43:10 +0000" as time AND creation time of it is '
            'less than or equal to "25 Jul 2019 10:43:10 +0000" as time) else (start time of it is greater than or '
            'equal to "01 Jan 2013 08:43:10 +0000" as time AND start time of it is less than or equal to "25 Jul 2019 '
            '10:43:10 +0000" as time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target'
            '></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)

    def test_three_combinedObser_operator_process(self):
        """
        to test 3 observation expression
        """
        stix_pattern = "([process:name = 'systemd' AND file:hashes.'SHA-256' = " \
                       "'58da5f0548e6a0889855d29fc839199b6e9e81cb945713d9ada586fcf7baee5a'] AND [file:name LIKE " \
                       "'rc.status' AND file:parent_directory_ref.path = '/etc'] OR [file:hashes.'SHA-256' = " \
                       "'97cc7eaf9e5b1e36eaf1f94bdb3b571e950aba38514f07d299f39719c9b91785' AND process:name = " \
                       "'systemd-udevd']) START t'2012-04-10T08:43:10.003Z' STOP t'2020-04-23T10:43:10.003Z'"
        query = translation.translate('bigfix', 'query', '{}', stix_pattern)
        query['queries'] = _remove_timestamp_from_query(query['queries'])

        queries = [
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | '
            '"n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", '
            'md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of processes whose (((sha256 of image file of it as string = '
            '"58da5f0548e6a0889855d29fc839199b6e9e81cb945713d9ada586fcf7baee5a" as string) AND (name of it as '
            'lowercase = "systemd" as lowercase)) AND (if (name of operating system as lowercase contains "win" as '
            'lowercase) then (creation time of it is greater than or equal to "10 Apr 2012 08:43:10 +0000" as time '
            'AND creation time of it is less than or equal to "23 Apr 2020 10:43:10 +0000" as time) else (start time '
            'of it is greater than or equal to "10 Apr 2012 08:43:10 +0000" as time AND start time of it is less than '
            'or equal to "23 Apr 2020 10:43:10 +0000" as '
            'time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>',
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>("file", name of it | "n/a",  "sha256", sha256 of it | "n/a","sha1", '
            'sha1 of it | "n/a","md5", md5 of it | "n/a",  pathname of it | "n/a",(modification time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of files whose (((name of it as string contains "rc.status" as '
            'string)) AND (modification time of it is greater than or equal to "10 Apr 2012 08:43:10 +0000" as time '
            'AND modification time of it is less than or equal to "23 Apr 2020 10:43:10 +0000" as time)) of folder ('
            '"/etc")</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>',
            '<BESAPI xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:noNamespaceSchemaLocation="BESAPI.xsd"><ClientQuery><ApplicabilityRelevance>true'
            '</ApplicabilityRelevance><QueryText>( "process", name of it | "n/a",  process id of it as string | '
            '"n/a", "sha256", sha256 of image file of it | "n/a",  "sha1", sha1 of image file of it | "n/a", "md5", '
            'md5 of image file of it | "n/a",  pathname of image file of it | "n/a",  (start time of it - "01 Jan '
            '1970 00:00:00 +0000" as time)/second) of processes whose (((name of it as string = "systemd-udevd" as '
            'string) AND (sha256 of image file of it as string = '
            '"97cc7eaf9e5b1e36eaf1f94bdb3b571e950aba38514f07d299f39719c9b91785" as string)) AND (if (name of '
            'operating system as lowercase contains "win" as lowercase) then (creation time of it is greater than or '
            'equal to "10 Apr 2012 08:43:10 +0000" as time AND creation time of it is less than or equal to "23 Apr '
            '2020 10:43:10 +0000" as time) else (start time of it is greater than or equal to "10 Apr 2012 08:43:10 '
            '+0000" as time AND start time of it is less than or equal to "23 Apr 2020 10:43:10 +0000" as '
            'time)))</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>']

        queries = _remove_timestamp_from_query(queries)
        self._test_query_assertions(query, queries)
