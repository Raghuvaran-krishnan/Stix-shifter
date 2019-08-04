__author__ = ["Muralidhar K, Aarthi Pushkala Sen Rajamanickam, Raghuvaran Krishnan, Jayapradha Sivaperuman,"
              " Amalraj Arockiam, Subhash Chandra Bose N, Annish Prashanth Stevin Shankar, Karthick Rajagopal"]
__copyright__ = "Copyright 2019, IBM Client"
__credits__ = ["Muralidhar K, Aarthi Pushkala Sen Rajamanickam, Raghuvaran Krishnan, Jayapradha Sivaperuman,"
              " Amalraj Arockiam, Subhash Chandra Bose N, Annish Prashanth Stevin Shankar, Karthick Rajagopal"]
__license__ = ""
__version__ = "1.0.3"
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
NETWORK = "network"
IMAGE_FILE = 'image file'
PROCESS_OBJECT = 'process'
FILE_OBJECT = 'file'
NETWORK_OBJECT = 'network'
DEFAULT_SEARCH_FOLDER = '"/root"'
HASHES_PROPERTY = '(sha256|sha1|md5)'
RELEVANCE_PROPERTY_MAP_JSON = "json/relevance_property_format_string_map.json"
START_STOP_PATTERN = "\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z"
QUALIFIER_COMP_TUPLE = ("greater than or equal to", "AND", "less than or equal to")
WHOSE_STRING = "whose ({})"
QUALIFIER = 'qualifier'


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
                    (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second) of processes {}''', 'network': '''
                    ("Local Address", local address of it as string | "n/a", 
                    "Remote Address", remote address of it as string | "n/a", "Local port", local port of it | -1, 
                    "remote port", remote port of it | -1, "Process name", names of processes of it) of sockets {}'''}

    def __init__(self, pattern: Pattern, data_model_mapper, result_limit, time_range):
        self.dmm = data_model_mapper
        self.pattern = pattern
        self.result_limit = result_limit
        self._time_range = time_range
        self.qualified_queries = []
        self.qualifier_string = ''
        self.search_folder = DEFAULT_SEARCH_FOLDER
        self._relevance_property_format_string_dict = self.load_json(RELEVANCE_PROPERTY_MAP_JSON)
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
        return map(lambda x: '"{}"'.format(x), values.element_iterator())

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
            return 'regex"({})"'.format(value.replace('%', '.*').replace('_', '.'))
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

    def _get_obj_of_obs_exp(self, expression):
        """
        Function to parse observation expression and return the object(i.e file, process, network) involved
        :param expression: expression object, ANTLR parsed exrepssion object
        :param relevance_map_dict: dict, relevance property format string
        :return: None
        """
        if hasattr(expression, 'object_path'):
            object_type = expression.object_path.split(':')[0]
            self._objects_in_obs_exp_dict[object_type] = self._relevance_property_format_string_dict.get\
                ('stix_property_to_observable_object_mapping').get(object_type)
            # self._objects_in_obs_exp = list(set(self._objects_in_obs_exp))
            temp_objects_in_obs_list = list(set(self._objects_in_obs_exp_dict.values()))
            temp_objects_in_obs_list.sort()
            self._objects_in_obs_exp_dict['object_type'] = self._relevance_property_format_string_dict. \
                get('combined_comp_exp_to_obs_obj_mapping').get('-'.join(temp_objects_in_obs_list)) \
                if len(temp_objects_in_obs_list) > 1 else temp_objects_in_obs_list[0]
        else:
            self._get_obj_of_obs_exp(expression.expr1)
            self._get_obj_of_obs_exp(expression.expr2)

    @staticmethod
    def _parse_time_range(qualifier, stix_obj, relevance_map_dict, comparator_tuple, time_range):
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
        try:
            if relevance_map_dict.get(QUALIFIER).get(stix_obj).get('add_timestamp_to_relevance'):
                compile_timestamp_regex = re.compile(START_STOP_PATTERN)
                transformer = TimestampToUTC()
                mapped_field = relevance_map_dict.get(QUALIFIER).get(stix_obj).get('mapped_field')
                if qualifier and compile_timestamp_regex.search(qualifier):
                    time_range_iterator = map(lambda x: transformer.transform(x.group()),
                                              compile_timestamp_regex.finditer(qualifier))
                # Default time range Start time = Now - 5 minutes and Stop time  = Now
                else:
                    stop_time = datetime.now()
                    start_time = stop_time - timedelta(minutes=time_range)
                    time_range_iterator = map(lambda x: transformer.transform(x, is_default=True), [start_time, stop_time])
                format_string = relevance_map_dict.get('property_format_string_mapping'). \
                    get(relevance_map_dict.get('qualifier').get(stix_obj).get('format_pattern')). \
                    format(mapped_field=mapped_field, comparator_1=comparator_tuple[0], start_value='"{}"'.
                           format(next(time_range_iterator)), comparator=comparator_tuple[1],
                           comparator_2=comparator_tuple[2], end_value='"{}"'.format(next(time_range_iterator)))
        except (KeyError, IndexError, TypeError) as e:
            raise e
        finally:
            return format_string

    @staticmethod
    def _parse_mapped_fields(stix_obj, value, comparator, mapped_fields_array, relevance_map_dict, _obj_in_obs_exp_dict):
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
        # To remove if greater than clause
        default_str = "default"
        comparator_str = "_comparator_property"
        comparison_string = ""
        temp_comparison_list = []
        mapped_fields_count = len(mapped_fields_array)
        for mapped_field in mapped_fields_array:
            if mapped_field.lower() != SEARCH_FOLDER:
                _obj_of_current_comp_exp = _obj_in_obs_exp_dict.get(stix_obj)
                comparator_format_string_key = relevance_map_dict.get(_obj_in_obs_exp_dict.get('object_type') +
                                                                      comparator_str).get(_obj_of_current_comp_exp)\
                    .get(comparator) if _obj_of_current_comp_exp in relevance_map_dict.\
                    get(_obj_in_obs_exp_dict.get('object_type') + comparator_str) and comparator in \
                    relevance_map_dict.get(_obj_in_obs_exp_dict.get('object_type') + comparator_str).\
                    get(_obj_of_current_comp_exp) else relevance_map_dict.\
                    get(default_str + comparator_str).get(comparator)
                value = value.replace('"', '') if value.replace('"', '').isdigit() else value
                if isinstance(value, str):
                    comparison_string += relevance_map_dict.get('property_format_string_mapping'). \
                        get(comparator_format_string_key).format(
                        mapped_field=mapped_field, comparator=comparator, value=value)
                # Case of handling IN operation
                else:
                    for each_value in value:
                        temp_comparison_list.append(relevance_map_dict.get('property_format_string_mapping').
                            get(comparator_format_string_key).format(
                            mapped_field=mapped_field, comparator=comparator, value=each_value))
                    comparison_string += "({})".format(' OR '.join(temp_comparison_list))
            # else:
            #     comparison_string = ''
            if mapped_fields_count > 1:
                comparison_string += " OR "
                mapped_fields_count -= 1
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
        if isinstance(expression, ComparisonExpression):  # Base Case
             # Resolve STIX Object Path to a field in the target Data Model
            stix_object, stix_field = expression.object_path.split(':')
            mapped_fields_array = self.dmm.map_field(stix_object, stix_field)
            # Below code is for handling [file:name = '*'] i.e all files
            if expression.value == '*':
                expression.comparator = ComparisonComparators.Matches
                expression.value = '.{}'.format(expression.value)
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
            comparison_string = self._parse_mapped_fields(stix_object, value, comparator, mapped_fields_array,
                                                          self._relevance_property_format_string_dict,
                                                          self._objects_in_obs_exp_dict)
            if SEARCH_FOLDER in mapped_fields_array:
                self.search_folder = value
            else:
                comparison_string = self.clean_format_string(comparison_string)
            if len(mapped_fields_array) > 1:
                # More than one data source field maps to the STIX attribute, so group comparisons together.
                grouped_comparison_string = "(" + comparison_string + ")"
                comparison_string = grouped_comparison_string
            if expression.negated:
                comparison_string = self._negate_comparison(comparison_string)
            # return "{}".format(comparison_string), stix_object
            return "{}".format(comparison_string)
        elif isinstance(expression, CombinedComparisonExpression):
            operator = self.comparator_lookup[expression.operator]
            # expression_01, object_type1 = self._parse_expression(expression.expr1)
            expression_01 = self._parse_expression(expression.expr1)
            # expression_02, object_type2 = self._parse_expression(expression.expr2)
            expression_02 = self._parse_expression(expression.expr2)
            # object_type = PROCESS_OBJECT if object_type2.lower() == PROCESS_OBJECT or \
            #                                 object_type1.lower() == PROCESS_OBJECT else FILE_OBJECT
            if not expression_01:
                # return "{}".format(expression_02), object_type
                return "{}".format(expression_02)
            elif not expression_02:
                # return "{}".format(expression_01), object_type
                return "{}".format(expression_01)
            else:
                # return "{} {} {}".format(expression_01, operator, expression_02), object_type
                return "{} {} {}".format(expression_01, operator, expression_02)
        elif isinstance(expression, ObservationExpression):
            self.search_folder = DEFAULT_SEARCH_FOLDER
            # self._objects_in_obs_exp, self._object_type = [], None
            self._objects_in_obs_exp_dict = {}
            self._get_obj_of_obs_exp(expression.comparison_expression)
            print (self._objects_in_obs_exp_dict)
            _object_type = self._objects_in_obs_exp_dict.get('object_type')
            # self.objects_in_obs_exp = list(set(self.objects_in_obs_exp))
            # self.objects_in_obs_exp.sort()
            # object_type = self._relevance_property_format_string_dict.\
            #     get('combined_comp_exp_to_obs_obj_mapping').get('-'.join(self.objects_in_obs_exp)) \
            #     if len(self.objects_in_obs_exp) > 1 else self.objects_in_obs_exp[0]
            # relevance_query, object_type = self._parse_expression(expression.comparison_expression, qualifier)
            relevance_query = self._parse_expression(expression.comparison_expression)
            # if _object_type == PROCESS_OBJECT:
            #     compile_regex_remove_image_string = re.compile('(?P<hashes_property>{}) of it'.format(HASHES_PROPERTY))
            #     for each_match in compile_regex_remove_image_string.finditer(relevance_query):
            #         relevance_query = compile_regex_remove_image_string.sub('{} of image file of it'.
            #                                                                 format(each_match.group('hashes_property')),
            #                                                                 relevance_query, count=1)
            self.qualifier_string = self._parse_time_range(qualifier, _object_type,
                                                           self._relevance_property_format_string_dict,
                                                           QUALIFIER_COMP_TUPLE, self._time_range)
            # if ADD_TIMESTAMP_TO_RELEVANCE or self._object_type == FILE_OBJECT:
            # if relevance_query:
            if self.qualifier_string:
                # Apply the time range to entire observation expression
                if relevance_query:
                    relevance_query = '({})'.format(relevance_query)
                    relevance_query += ' AND '+self.qualifier_string
                else:
                    relevance_query += self.qualifier_string
            # else:
            #     relevance_query += self.qualifier_string
            relevance_query = WHOSE_STRING.format(relevance_query) if relevance_query else ''
            temp_qry_closing_dict = self._relevance_property_format_string_dict.get('relevance_qry_closing_string')
            closing_relevance_string = eval(temp_qry_closing_dict.get(_object_type).get('format_string')) if \
                temp_qry_closing_dict.get(_object_type).get('add_qry_closing_string') and \
                temp_qry_closing_dict.get(_object_type).get('format_string') else ""
            # if self._object_type.lower() == PROCESS_OBJECT:
            #     closing_relevance_string = ""
            # elif self._object_type.lower() == NETWORK_OBJECT:
            #     closing_relevance_string = " of {}".format(NETWORK)
            # else:
            #     closing_relevance_string = " of {} ({})".format(SEARCH_FOLDER, self.search_folder)
            # closing_relevance_string = closing_relevance_string if relevance_query else closing_relevance_string.lstrip()
            final_comparison_exp = self.clean_format_string(self.stix_object_format_string_lookup_dict.
                                                            get(_object_type)).format(relevance_query)
            final_comparison_exp += closing_relevance_string
            self.qualified_queries.append(final_comparison_exp)
            return None
        elif isinstance(expression, CombinedObservationExpression):
            # expression_01 = self._parse_expression(expression.expr1, qualifier)
            expression_01 = self._parse_expression(expression.expr1)
            # expression_02 = self._parse_expression(expression.expr2, qualifier)
            expression_02 = self._parse_expression(expression.expr2)
            if expression_01 and expression_02:
                self.qualified_queries.extend([expression_01, expression_02])
            elif expression_01:
                self.qualified_queries.append(expression_01)
            elif expression_02:
                self.qualified_queries.append(expression_02)
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
