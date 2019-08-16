__author__ = ["Muralidhar K, Aarthi Pushkala Sen Rajamanickam, Raghuvaran Krishnan, Jayapradha Sivaperuman,"
              " Amalraj Arockiam, Subhash Chandra Bose N, Annish Prashanth Stevin Shankar, Karthick Rajagopal"]
__copyright__ = "Copyright 2019, IBM Client"
__credits__ = ["Muralidhar K, Aarthi Pushkala Sen Rajamanickam, Raghuvaran Krishnan, Jayapradha Sivaperuman,"
              " Amalraj Arockiam, Subhash Chandra Bose N, Annish Prashanth Stevin Shankar, Karthick Rajagopal"]
__license__ = ""
__version__ = "1.1.0"
__maintainer__ = "Muralidhar K"
__email__ = "Muralidhar K-ERS,HCLTech <murali_k@hcl.com>"
__status__ = "Development"

from stix_shifter.stix_translation.src.patterns.pattern_objects import ObservationExpression, ComparisonExpression, \
    ComparisonExpressionOperators, ComparisonComparators, Pattern, \
    CombinedComparisonExpression, CombinedObservationExpression, ObservationOperators, StartStopQualifier
import json
import os.path as path
from stix_shifter.stix_translation.src.utils.transformers import TimestampToUTC
from datetime import datetime, timedelta
import re
import logging

logger = logging.getLogger(__name__)
SEARCH_FOLDER = 'folder'
SOCKET = "socket"
NETWORK = "network"
FILE = "file"
DEFAULT_SEARCH_FOLDER = '"/root"'
RELEVANCE_PROPERTY_MAP_JSON = "json/relevance_property_format_string_map.json"
START_STOP_PATTERN = "\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z"
WHOSE_STRING = "whose ({})"


class RelevanceQueryStringPatternTranslator:
    """
    Stix to Native query translation
    """
    comparator_lookup = {
        ComparisonExpressionOperators.And: "AND",
        ComparisonExpressionOperators.Or: "OR",
        ComparisonComparators.Equal: "=",
        ComparisonComparators.NotEqual: "!=",
        ComparisonComparators.Like: "contains",
        ComparisonComparators.Matches: "matches",
        ComparisonComparators.GreaterThan: "is greater than",
        ComparisonComparators.GreaterThanOrEqual: "is greater than or equal to",
        ComparisonComparators.LessThan: "is less than",
        ComparisonComparators.LessThanOrEqual: "is less than or equal to",
        ComparisonComparators.In: "=",
        ObservationOperators.Or: 'OR',
        ObservationOperators.And: 'OR'
    }

    stix_object_format_string_lookup_dict = {'file': '''("file", name of it | "n/a",
                    "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",
                    pathname of it | "n/a",(modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second)  
                    of files {}''', 'process': '''( "process", name of it | "n/a",
                    process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",
                    "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",
                    pathname of image file of it | "n/a",
                    (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes {}''', 'socket': '''
                    ("Local Address", local address of it as string | "n/a", "Remote Address", remote address of it 
                    as string | "n/a", "Local port", local port of it | -1, "remote port", remote port of it | -1, 
                    "Process name", names of processes of it, pid of process of it,
                    (if (name of operating system as lowercase contains "win" as lowercase) then 
                    ("Creation time", (creation time of process of it - "01 Jan 1970 00:00:00 +0000" as time)/second) 
                    else ("Start time", (start time of process of it - "01 Jan 1970 00:00:00 +0000" as time)/second)), 
                    "TCP", tcp of it, "UDP", udp of it) of sockets {}'''}

    def __init__(self, pattern: Pattern, data_model_mapper, result_limit, time_range):
        self.dmm = data_model_mapper
        self.pattern = pattern
        self.result_limit = result_limit
        self._time_range = time_range
        self.qualified_queries = []
        self.qualifier_string = ''
        self.search_folder = DEFAULT_SEARCH_FOLDER
        self._master_obj = None
        self._relevance_string_list = []
        self._relevance_property_format_string_dict = self.load_json(RELEVANCE_PROPERTY_MAP_JSON)
        self._time_range_comparator_list = [self.comparator_lookup.get(each) for each in
                                            (ComparisonComparators.GreaterThanOrEqual, ComparisonComparators.LessThanOrEqual)]
        self.parse_expression(pattern)

    @staticmethod
    def load_json(rel_path_of_file):
        """
        Consumes the relevance property format string mapping json and returns a dictionary

        :param rel_path_of_file: str, path of relevance property format string mapping json file
        :return: dictionary
        """
        relevance_json_path = path.abspath(path.join(path.join(__file__, ".."), rel_path_of_file))
        if path.exists(relevance_json_path):
            with open(relevance_json_path) as f_obj:
                return json.load(f_obj)
        else:
            raise FileNotFoundError

    @staticmethod
    def _format_equality(value) -> str:
        """
        Formatting value in the event of equality operation
        :param value: str
        :return: str
        """
        return '"{}"'.format(value)

    @staticmethod
    def _format_set(values) -> str:
        """
        Formatting list of values in the event of IN operation
        :param values: str
        :return: list
        """
        return list(map(lambda x: '"{}"'.format(x), values.element_iterator()))


    @staticmethod
    def _format_like(value) -> str:
        """
        Formatting value in the event of LIKE operation
        :param value: str
        :return: str
        """
        # Replacing value with % to .* and _ to . for supporting Like comparator
        compile_regex = re.compile('.*(\%|\_).*')
        if compile_regex.match(value):
            return 'regex"({}$)"'.format(value.replace('%', '.*').replace('_', '.'))
        else:
            return '"{}"'.format(value)

    @staticmethod
    def _format_matches(value) -> str:
        """
        Formatting value in the event of MATCHES operation
        :param value: str
        :return: str
        """
        value = value.replace('\\', '&#92;')
        return 'regex"({})"'.format(value)

    def get_master_obj_of_obs_exp(self, expression, objects_list):
        """
        Function to parse observation expression and return the object(i.e file, process, network) involved
        :param expression: expression object, ANTLR parsed exrepssion object
        :param relevance_map_dict: dict, relevance property format string
        :return: None
        """
        if hasattr(expression, 'object_path'):
            stix_object, stix_field = expression.object_path.split(':')
            mapped_field = self.dmm.map_field(stix_object, stix_field)[0]
            current_comparison_obj = mapped_field.split('.')[0]
            try:
                if objects_list.index(current_comparison_obj) > objects_list.index(self._master_obj):
                    self._master_obj = current_comparison_obj
            except ValueError:
                raise ValueError("Unmapped object: {}. Please check from_stix json".format(current_comparison_obj))
        else:
            self.get_master_obj_of_obs_exp(expression.expr1, objects_list)
            self.get_master_obj_of_obs_exp(expression.expr2, objects_list)

    @staticmethod
    def _parse_time_range(qualifier, stix_obj, relevance_map_dict, time_range, range_operator_list):
        """
        Format the input time range i.e <START|STOP>t'2019-04-20T10:43:10.003Z to
        %d %b %Y %H:%M:%S %z"(i.e 23 Oct 2018 12:20:14 +0000)
        :param qualifier: str, input time range i.e START t'2019-04-10T08:43:10.003Z' STOP t'2019-04-20T10:43:10.003Z'
        :param stix_obj: str, file or process stix object
        :param relevance_map_dict: dict, relevance property format string
        :param comparator_tuple: tuple, ("greater than or equal to", "AND", "less than or equal to")
        :param time_range: int, value available from main.py in options variable
        :return: str, format_string bound with time range provided
        """
        format_string = ''
        format_string_list = []
        qualifier_master_dict = {
            "file":
                {
                    "mapped_field": ["modification time"],
                    "extra_mapped_string": "",
                    "transformer": "as time",
                    "format_pattern": "format_string_range",
                    "add_timestamp_to_relevance": 1,
                    "os_dependency": 0
                },
            "process":
                {
                    "mapped_field": ["creation time", "start time"],
                    "extra_mapped_string": "",
                    "transformer": "as time",
                    "format_pattern": "format_string_range",
                    "add_timestamp_to_relevance": 1,
                    "os_dependency": 1
                },
            "socket":
                {
                    "mapped_field": ["creation time", "start time"],
                    "extra_mapped_string": " of process",
                    "transformer": "as time",
                    "format_pattern": "format_string_range",
                    "add_timestamp_to_relevance": 1,
                    "os_dependency": 1
                }
        }
        condition_format_for_time = """(if (name of operating system as lowercase contains "win" as lowercase) then 
        {time_exp1} else {time_exp2})"""
        qualifier_keys_list = ['mapped_field', 'extra_mapped_string', 'transformer']
        try:
            if qualifier_master_dict.get(stix_obj).get('add_timestamp_to_relevance'):
                compile_timestamp_regex = re.compile(START_STOP_PATTERN)
                transformer = TimestampToUTC()
                mapped_field, extra_mapped_string, str_transformer = [qualifier_master_dict.get(
                    stix_obj).get(each_key) for each_key in qualifier_keys_list]
                if qualifier and compile_timestamp_regex.search(qualifier):
                    time_range_iterator = map(lambda x: transformer.transform(x.group()),
                                              compile_timestamp_regex.finditer(qualifier))
                # Default time range Start time = Now - 5 minutes and Stop time  = Now
                else:
                    stop_time = datetime.now()
                    start_time = stop_time - timedelta(minutes=time_range)
                    time_range_iterator = map(lambda x: transformer.transform(x, is_default=True),
                                              [start_time, stop_time])
                time_range_tuple = [each for each in time_range_iterator]
                for each in mapped_field:
                    interim_format_string_list = []
                    for index_op, each_operator in enumerate(range_operator_list):
                        interim_format_string_list.append(relevance_map_dict.get('format_string').
                                                          get(qualifier_master_dict.get(stix_obj).get('format_pattern'))
                                                          .format(mapped_field=each,
                                                                  extra_mapped_string=extra_mapped_string,
                                                                  comparator=each_operator, start_value='"{}"'.
                                                                  format(time_range_tuple[index_op]),
                                                                  transformer=str_transformer))
                    format_string_list.append('({})'.format(' AND '.join(interim_format_string_list)))
                if qualifier_master_dict.get(stix_obj).get('os_dependency'):
                    format_string = condition_format_for_time.format(time_exp1=format_string_list[0],
                                                                     time_exp2=format_string_list[1])
                else:
                    format_string = ' '.join(format_string_list)
            return format_string
        except (KeyError, IndexError, TypeError) as e:
            raise e

    def get_field_relevance_qry(self, current_obj, master_obj):
        if current_obj != master_obj:
            parent_obj_references_dict = self._relevance_property_format_string_dict.get('object_hierarchy').\
                get(master_obj).get('reference')
            if parent_obj_references_dict:
                for each_key in parent_obj_references_dict:
                    self._relevance_string_list.insert(0, parent_obj_references_dict.get(each_key))
                    if current_obj == each_key:
                        break
                    else:
                        self.get_field_relevance_qry(current_obj, each_key)

    @staticmethod
    def _parse_mapped_fields(value, comparator, mapped_fields_array, relevance_string_list, relevance_map_dict):
        """
        Mapping the stix object property with their corresponding property in relevance query
        from_stix_map.json will be used for mapping
        :param expression: expression object, ANTLR parsed exrepssion object
        :param value: str
        :param comparator: str
        :param mapped_fields_array: list, Mapping available in from_stix_map.json
        :param relevance_map_dict: dict, relevance_property_format_string_map.json
        :return: str, whose part of the relevance query for each value
        """

        operator_mapping = {"default": "format_string_generic", "matches": "format_string_match"}
        comparison_string = ""
        if isinstance(value, list):
            comparison_string_list = [[] for _ in value]
        for index_of_field, mapped_field in enumerate(mapped_fields_array):
            mapped_field = mapped_field.split('.')[-1]
            if mapped_field.lower() != SEARCH_FOLDER:
                mapped_field = "{} of ".format(mapped_field) if relevance_string_list else mapped_field
                mapped_field_relevance_string = "{} {} of it".format(mapped_field, ' of '.join(
                    relevance_string_list)).lstrip()
                format_string_key = operator_mapping.get(comparator) if comparator in operator_mapping \
                    else operator_mapping.get('default')
                if isinstance(value, list):
                    value = [each.replace('"', '') if each.replace('"', '').isdigit() else each for each in list(value)]
                    transformer = 'as lowercase' if value[0].replace('"', '').isalpha() else ''if \
                        value[0].replace('"', '').isdigit() else 'as string'
                else:
                    value = value.replace('"', '') if value.replace('"', '').isdigit() else value
                    transformer = 'as lowercase' if value.replace('"', '').isalpha() else ''if \
                        value[0].replace('"', '').isdigit() else 'as string'
                    # If Comparator is "contains" then convert the property to "as string"
                    if comparator == 'contains':
                        transformer = 'as string'
                if isinstance(value, str):
                    transformer_field, transformer_value = (transformer, '') \
                                                       if (value.startswith('regex') and comparator == 'contains') \
                                                       else (transformer, transformer)
                    comparison_string += relevance_map_dict.get('format_string'). \
                        get(format_string_key).format(
                        mapped_field=mapped_field_relevance_string, transformer_field=transformer_field,
                        comparator=comparator, value=value, transformer_value=transformer_value)
                    if index_of_field < len(mapped_fields_array)-1:
                        comparison_string += " OR "
                    # Encapsulating within () if mapped_field_array > 1
                    else:
                        comparison_string = '({})'.format(comparison_string)
                # Case of handling IN operation
                else:
                    for index, each_value in enumerate(value):
                        comparison_string_list[index].append(relevance_map_dict.get('format_string').
                                                             get(format_string_key).
                                                             format(mapped_field=mapped_field_relevance_string,
                                                                    transformer_field=transformer, comparator=comparator,
                                                                    value=each_value, transformer_value=transformer))
        if isinstance(value, list):
            comparison_string += '({})'.format(' OR '.join('({})'.format(' OR '.join(each)) for each in
                                               comparison_string_list))
        return comparison_string

    @staticmethod
    def clean_format_string(format_string):
        """
        Formats and replaces carriage return(\r), newline character(\n), spaces > 2, tab with 1 space
        :param format_string: str
        :return: str
        """
        return re.sub('\r|\n|\s{2,}|\t', ' ', format_string)

    def _parse_expression(self, expression, qualifier=None):
        """
        Complete formation of relevance query from ANTLR expression object
        :param expression: expression object, ANTLR parsed exrepssion object
        :param qualifier: str, default in None
        :return: None or relevance query as the method call is recursive
        """
        relevance_qry_termination_string = {
            "file":
                {
                    "add_qry_closing_string": 1,
                    "format_string": " of {} ({})"
                },
            "socket":
                {
                    "add_qry_closing_string": 1,
                    "format_string": " of {}"
                },
            "process":
                {
                    "add_qry_closing_string": 1,
                    "format_string": ""
                }
        }
        if isinstance(expression, ComparisonExpression):  # Base Case
            self._relevance_string_list = []
            stix_object, stix_field = expression.object_path.split(':')
            mapped_fields_array = self.dmm.map_field(stix_object, stix_field)
            comparator = self.comparator_lookup[expression.comparator]
            if expression.comparator == ComparisonComparators.In:
                value = self._format_set(expression.value)
            elif expression.comparator in [ComparisonComparators.Equal, ComparisonComparators.NotEqual,
                                           ComparisonComparators.GreaterThan,
                                           ComparisonComparators.GreaterThanOrEqual, ComparisonComparators.LessThan,
                                           ComparisonComparators.LessThanOrEqual]:
                value = self._format_equality(expression.value)
            # '%' -> '*' wildcard, '_' -> '?' single wildcard
            elif expression.comparator == ComparisonComparators.Like:
                value = self._format_like(expression.value)
            elif expression.comparator == ComparisonComparators.Matches:
                value = self._format_matches(expression.value)
            else:
                raise NotImplementedError("Unknown comparison operator {}.".format(expression.comparator))
            self.get_field_relevance_qry(mapped_fields_array[0].split('.')[0], self._master_obj)
            comparison_string = self._parse_mapped_fields(value, comparator,
                                                          mapped_fields_array, self._relevance_string_list,
                                                          self._relevance_property_format_string_dict)
            if '{}.{}'.format(FILE, SEARCH_FOLDER) in mapped_fields_array:
                self.search_folder = value
            else:
                comparison_string = self.clean_format_string(comparison_string)
            if expression.negated:
                comparison_string = self._negate_comparison(comparison_string)
            return "{}".format(comparison_string)
        elif isinstance(expression, CombinedComparisonExpression):
            operator = self.comparator_lookup[expression.operator]
            expression_01 = self._parse_expression(expression.expr1)
            expression_02 = self._parse_expression(expression.expr2)
            if not expression_01:
                return "{}".format(expression_02)
            elif not expression_02:
                return "{}".format(expression_01)
            else:
                return "{} {} {}".format(expression_01, operator, expression_02)
        elif isinstance(expression, ObservationExpression):
            self.search_folder = DEFAULT_SEARCH_FOLDER
            objects_hierarchy_dict = self._relevance_property_format_string_dict.get('object_hierarchy')
            objects_list = list(objects_hierarchy_dict.keys())
            self._master_obj = objects_list[0]
            self.get_master_obj_of_obs_exp(expression.comparison_expression, objects_list)
            relevance_query = self._parse_expression(expression.comparison_expression)
            self.qualifier_string = self._parse_time_range(qualifier, self._master_obj,
                                                           self._relevance_property_format_string_dict
                                                           , self._time_range, self._time_range_comparator_list)
            self.qualifier_string = self.clean_format_string(self.qualifier_string)
            if self.qualifier_string:
                # Apply the time range to entire observation expression
                if relevance_query:
                    relevance_query = '({})'.format(relevance_query)
                    relevance_query += ' AND '+self.qualifier_string
                else:
                    relevance_query += self.qualifier_string
            relevance_query = WHOSE_STRING.format(relevance_query) if relevance_query else ''
            closing_relevance_string = relevance_qry_termination_string.get(self._master_obj).get('format_string') if \
                relevance_qry_termination_string.get(self._master_obj).get('add_qry_closing_string') and \
                relevance_qry_termination_string.get(self._master_obj).get('format_string') else ""
            if self._master_obj == FILE:
                closing_relevance_string = closing_relevance_string.format(SEARCH_FOLDER, self.search_folder)
            elif self._master_obj == SOCKET:
                closing_relevance_string = closing_relevance_string.format(NETWORK)
            final_comparison_exp = self.clean_format_string(self.stix_object_format_string_lookup_dict.
                                                            get(self._master_obj)).format(relevance_query)
            final_comparison_exp += closing_relevance_string
            self.qualified_queries.append(final_comparison_exp)
            return None
        elif isinstance(expression, CombinedObservationExpression):
            expression_01 = self._parse_expression(expression.expr1, qualifier)
            expression_02 = self._parse_expression(expression.expr2, qualifier)
            if expression_01 and expression_02:
                self.qualified_queries.extend([expression_01, expression_02])
        elif isinstance(expression, StartStopQualifier):
            if hasattr(expression, 'observation_expression'):
                return self._parse_expression(getattr(expression, 'observation_expression'), expression.qualifier)
        elif isinstance(expression, Pattern):
            return self._parse_expression(expression.expression)
        else:
            raise RuntimeError("Unknown Recursion Case for expression={}, type(expression)={}".format(
                expression, type(expression)))

    def parse_expression(self, pattern: Pattern):
        """
        parse_expression --> Native query
        :param pattern: expression object, ANTLR parsed exrepssion object
        :return:str, relevance query(native query)
        """
        return self._parse_expression(pattern)


def translate_pattern(pattern: Pattern, data_model_mapper, options):
    """
    Conversion of expression object to XML query
    :param pattern: expression object, ANTLR parsed exrepssion object
    :param data_model_mapper: DataMapper object, mapping object obtained by parsing from_stix_map.json
    :param options: dict, contains 2 keys result_limit defaults to 10000, timerange defaults to 5
    :return: str, XML query with relevance query embedded inside <QueryText> tag
    """
    result_limit = options['result_limit']
    timerange = options['timerange']
    list_final_query = []
    translated_dictionary = RelevanceQueryStringPatternTranslator(pattern, data_model_mapper, result_limit, timerange)
    final_query = translated_dictionary.qualified_queries
    for each_query in final_query:
        besapi_query = '<BESAPI xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"BESAPI.xsd\"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>' + \
        each_query + '</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>'
        list_final_query.append(besapi_query)
    return list_final_query
