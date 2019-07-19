from stix_shifter.stix_translation.src.patterns.pattern_objects import ObservationExpression, ComparisonExpression, \
    ComparisonExpressionOperators, ComparisonComparators, Pattern, \
    CombinedComparisonExpression, CombinedObservationExpression, ObservationOperators, StartStopQualifier
import json
import os.path as path
from stix_shifter.stix_translation.src.utils.transformers import TimestampToUTC
from stix_shifter.stix_translation.src.patterns.errors import SearchFeatureNotSupportedError
import re
import logging

logger = logging.getLogger(__name__)
SEARCH_FOLDER = 'search_folder'
PROCESS_OBJECT = 'process'
FILE_OBJECT = 'file'
DEFAULT_SEARCH_FOLDER = '"/root"'
RELEVANCE_PROPERTY_MAP_JSON = "json/relevance_property_format_string_map.json"
START_STOP_PATTERN = "\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z"


class RelevanceQueryStringPatternTranslator:
    comparator_lookup = {
        ComparisonExpressionOperators.And: "AND",
        ComparisonExpressionOperators.Or: "OR",
        ComparisonComparators.Equal: "=",
        ComparisonComparators.NotEqual: "!=",
        ComparisonComparators.Like: "contains",
        ComparisonComparators.Matches: "matches",
        ComparisonComparators.LessThanOrEqual: "%lt;",
        ComparisonComparators.LessThan: "%lt;",
        ComparisonComparators.GreaterThanOrEqual: "%gt;",
        ComparisonComparators.GreaterThan: "%gt;",
        ObservationOperators.Or: 'OR',
        # Treat AND's as OR's -- Unsure how two ObsExps wouldn't cancel each other out.
        ObservationOperators.And: 'OR'
    }

    like_wildcard_lookup = {
        '%': '*',
        '-': '?',
        '[]': '[]',
        '^': '!'
    }

    stix_object_format_string_lookup_dict = {'file': '''("file", name of it | "n/a",
                    "sha256", sha256 of it | "n/a","sha1", sha1 of it | "n/a","md5", md5 of it | "n/a",
                    pathname of it | "n/a",
                    (modification time of it - "01 Jan 1970 00:00:00 +0000" as time)/second )
                    of files whose ({})''', 'process': '''( "process", name of it | "n/a",
                     process id of it as string | "n/a", "sha256", sha256 of image file of it | "n/a",
                      "sha1", sha1 of image file of it | "n/a", "md5", md5 of image file of it | "n/a",
                       pathname of image file of it | "n/a",
                        (start time of it - "01 Jan 1970 00:00:00 +0000" as time)/second ) of processes whose ({})'''}

    # query_format = {
    #     "all_files_in_directory": "(\"file\", name of it | \"n/a\", \"sha256\", sha256 of it | \"n/a\", \"sha1\", sha1 of it | \"n/a\", \"md5\", md5 of it | \"n/a\", pathname of it | \"n/a\", (modification time of it - \"01 Jan 1970 00:00:00 +0000\" as time)/second ) of files of folder (\"{file_path}\")",
    #     "file_query": "(\"file\", name of it | \"n/a\", \"sha256\", sha256 of it | \"n/a\", \"sha1\", sha1 of it | \"n/a\", \"md5\", md5 of it | \"n/a\", pathname of it | \"n/a\", (modification time of it - \"01 Jan 1970 00:00:00 +0000\" as time)/second ) of files whose ({stix_object} of it as lowercase {object_value} as lowercase) of folder (\"{file_path}\")",
    #     "file_name_with_hash": "(\"file\", name of it | \"n/a\", \"sha256\", sha256 of it | \"n/a\", \"sha1\", sha1 of it | \"n/a\", \"md5\", md5 of it | \"n/a\", pathname of it | \"n/a\", (modification time of it - \"01 Jan 1970 00:00:00 +0000\" as time)/second ) of files whose ({name_object} of it as lowercase {file_name} as lowercase {expression_operator} {hash_type} of it as lowercase {hash_value} as lowercase) of folder (\"{file_path}\")",
    #     "all_processes": "( \"process\", name of it | \"n/a\", process id of it as string | \"n/a\", \"sha256\", sha256 of image file of it | \"n/a\", \"sha1\", sha1 of image file of it | \"n/a\", \"md5\", md5 of image file of it | \"n/a\", pathname of image file of it | \"n/a\", (start time of it - \"01 Jan 1970 00:00:00 +0000\" as time)/second ) of processes",
    #     "filter_processes_with_name": "( \"process\", name of it | \"n/a\", process id of it as string | \"n/a\", \"sha256\", sha256 of image file of it | \"n/a\", \"sha1\", sha1 of image file of it | \"n/a\", \"md5\", md5 of image file of it | \"n/a\", pathname of image file of it | \"n/a\", (start time of it - \"01 Jan 1970 00:00:00 +0000\" as time)/second ) of processes whose ({process_object} of it as lowercase {process_name} as lowercase )",
    #     "process_hash_query": "( \"process\", name of it | \"n/a\", process id of it as string | \"n/a\", \"sha256\", sha256 of image file of it | \"n/a\", \"sha1\", sha1 of image file of it | \"n/a\", \"md5\", md5 of image file of it | \"n/a\", pathname of image file of it | \"n/a\", (start time of it - \"01 Jan 1970 00:00:00 +0000\" as time)/second ) of processes whose ({hash_type} of image file of it as lowercase {hash_value} as lowercase )",
    #     "process_name_with_hash": "( \"process\", name of it | \"n/a\", process id of it as string | \"n/a\", \"sha256\", sha256 of image file of it | \"n/a\", \"sha1\", sha1 of image file of it | \"n/a\", \"md5\", md5 of image file of it | \"n/a\", pathname of image file of it | \"n/a\", (start time of it - \"01 Jan 1970 00:00:00 +0000\" as time)/second ) of processes whose ({process_object} of it as lowercase {process_name} as lowercase {expression_operator} {hash_type} of image file of it as lowercase {hash_value} as lowercase )"
    # }

    query_string = {}
    query_type = ""

    @staticmethod
    def load_json(rel_path_of_file):
        relevance_json_path = path.abspath(path.join(path.join(__file__, ".."), rel_path_of_file))
        if path.exists(relevance_json_path):
            with open(relevance_json_path) as f_obj:
                return json.load(f_obj)
        else:
            raise FileNotFoundError

    def __init__(self, pattern: Pattern, data_model_mapper, result_limit):
        self.dmm = data_model_mapper
        self.pattern = pattern
        self.result_limit = result_limit
        # self.translated = self.parse_expression(pattern)
        # self.queries = self.translated
        # List for any queries that are split due to START STOP qualifier
        self.qualified_queries = []
        self.qualifier_string = ''
        self.is_combined_observation = False
        self.is_qualifier_exp_generated = False
        self.search_folder = DEFAULT_SEARCH_FOLDER
        # Translated query string without any qualifiers
        self._relevance_property_format_string_dict = self.load_json(RELEVANCE_PROPERTY_MAP_JSON)
        self.parse_expression(pattern)

        # self.qualified_queries.append(self.translated)

        # To be considered if timestamp qualifier comes into picture
        # WILL COMMENT OUT FOR NOW
        # self.qualified_queries = _format_translated_queries(self.qualified_queries)

    @staticmethod
    def _format_equality(value) -> str:
        return '"{}"'.format(value)

    @staticmethod
    def _format_set(values) -> str:
        gen = values.element_iterator()
        return "({})".format(' OR '.join(['"{}"'.format(value) for value in gen]))

    @staticmethod
    def _format_like(value) -> str:
        # Replacing value with % to * and _ to ? for to support Like comparator
        if isinstance(value, str):
            return '"{}"'.format(value.replace('%', '*').replace('_', '?'))
        else:
            return value

    @staticmethod
    def _format_matches(value) -> str:
        return 'regex "({})"'.format(value)

    @staticmethod
    def _escape_value(value, comparator=None) -> str:
        if isinstance(value, str):
            return '{}'.format(value.replace('\\', '\\\\').replace('\"', '\\"').replace('(', '\\(').replace(')', '\\)'))
        else:
            return value

    def _parse_expression(self, expression, qualifier=None):
        if isinstance(expression, ComparisonExpression):  # Base Case
             # Resolve STIX Object Path to a field in the target Data Model
            stix_object, stix_field = expression.object_path.split(':')
            # Added newly
            mapped_fields_array = self.dmm.map_field(stix_object, stix_field)
            comparator = self.comparator_lookup[expression.comparator]
            # if stix_field == 'start' or stix_field == 'end':
            #     transformer = TimestampToUTC()
            #     expression.value = transformer.transform(expression.value)
            if expression.comparator == ComparisonComparators.In:
                value = self._format_set(expression.value)
            elif expression.comparator == ComparisonComparators.Equal or \
                    expression.comparator == ComparisonComparators.NotEqual:

                value = self._format_equality(expression.value)
            # '%' -> '*' wildcard, '_' -> '?' single wildcard
            # No need to format value for Like for now
            # If needed to change later
            elif expression.comparator == ComparisonComparators.Like:
                value = expression.value
            elif expression.comparator == ComparisonComparators.Matches:
                # STILL UNDER IMPLEMENTATION
                value = self._format_matches(expression.value)
            else:
                value = self._escape_value(expression.value)
            comparison_string = self._parse_mapped_fields(expression, value, comparator, mapped_fields_array,
                                                          self._relevance_property_format_string_dict)
            if SEARCH_FOLDER in mapped_fields_array:
                self.search_folder = value
                comparison_string = ''
            else:
                comparison_string = self.clean_format_string(comparison_string)
            if len(mapped_fields_array) > 1:
                # More than one data source field maps to the STIX attribute, so group comparisons together.
                grouped_comparison_string = "(" + comparison_string + ")"
                comparison_string = grouped_comparison_string
            if expression.negated:
                comparison_string = self._negate_comparison(comparison_string)
            if qualifier and not self.is_qualifier_exp_generated:
                self.qualifier_string = self._parse_time_range(qualifier)
                self.is_qualifier_exp_generated = True
            comparison_string += self.qualifier_string
            # if qualifier:
            #     self.qualified_queries.append("{} AND {}".format(comparison_string, qualifier))
            #     return '', stix_object
            # else:
            #     return "{}".format(comparison_string), stix_object
            return "{}".format(comparison_string), stix_object

        # TODO
        # ----- IMPORTANT -------
        # We may have to modify the below as well for further input cases
        elif isinstance(expression, CombinedComparisonExpression):
            operator = self.comparator_lookup[expression.operator]
            expression_01, object_type1 = self._parse_expression(expression.expr1)
            expression_02, object_type2 = self._parse_expression(expression.expr2)
            object_type = PROCESS_OBJECT if object_type2.lower() == PROCESS_OBJECT or \
                            object_type1.lower() == PROCESS_OBJECT else FILE_OBJECT
            if not expression_01:
                return "{}".format(expression_02), object_type
            elif not expression_02:
                return "{}".format(expression_01), object_type
            else:
                return "{} {} {}".format(expression_01, operator, expression_02), object_type
            # if not expression_01 or not expression_02:
            #     return ''
            # if isinstance(expression.expr1, CombinedComparisonExpression):
            #     expression_01 = "({})".format(expression_01)
            # if isinstance(expression.expr2, CombinedComparisonExpression):
            #     expression_02 = "({})".format(expression_02)
            # query_string = "{} {} {}".format(expression_01, operator, expression_02)
            # if qualifier is not None:
            #     self.qualified_queries.append("{} {}".format(query_string, qualifier))
            #     return ''
            # else:
                # return "{}".format(query_string) # changed like below
                # self.qualified_queries.append(query_string)
                # return self.remove_unwanted_space(self.stix_object_format_string_lookup_dict.get("file").
                #               format("({})".format(query_string)))
        elif isinstance(expression, CombinedObservationExpression):
            self.is_combined_observation = True
            operator = self.comparator_lookup[expression.operator]
            expression_01 = self._parse_expression(expression.expr1, qualifier)
            expression_02 = self._parse_expression(expression.expr2, qualifier)
            if expression_01 and expression_02:
                self.qualified_queries.append("({}) $$$${}#### ({})".format(expression_01, operator, expression_02))
            elif expression_01:
                self.qualified_queries.append("$$$${}#### {}".format(operator, expression_01))
            elif expression_02:
                self.qualified_queries.append("$$$${}#### {}".format(operator, expression_02))
            # else:
            #     return ''
        elif isinstance(expression, ObservationExpression):
            # self.search_folder = '"/root"' # TODO
            relevance_query, object_type = self._parse_expression(expression.comparison_expression, qualifier)
            if object_type.lower() == PROCESS_OBJECT:
                folder_relevance_string = ""
            else:
                # if not self.search_folder:
                #     self.search_folder = DEFAULT_SEARCH_FOLDER
                folder_relevance_string = " of folder ({})".format(self.search_folder)
            final_comparison_exp = self.clean_format_string(self.stix_object_format_string_lookup_dict.
                                                              get(object_type)).format(relevance_query)
            final_comparison_exp += folder_relevance_string
            if self.is_combined_observation:
                return final_comparison_exp
            else:
                self.qualified_queries.append(final_comparison_exp)
        # elif hasattr(expression, 'qualifier') and hasattr(expression, 'observation_expression'):
        #     if isinstance(expression.observation_expression, CombinedObservationExpression):
        #         operator = self.comparator_lookup[expression.observation_expression.operator]
        #         expression_01 = self._parse_expression(expression.observation_expression.expr1)
        #         expression_02 = self._parse_expression(expression.observation_expression.expr2, expression.qualifier)
        #
        #         if expression_01:
        #             return "{expr1}".format(expr1=expression_01)
        #     else:
        #         return self._parse_expression(expression.observation_expression.comparison_expression, expression.qualifier)
        elif isinstance(expression, Pattern):
            return self._parse_expression(expression.expression)
        elif isinstance(expression, StartStopQualifier):
            if hasattr(expression, 'observation_expression'):
                return self._parse_expression(getattr(expression, 'observation_expression'), expression.qualifier)
        else:
            raise RuntimeError("Unknown Recursion Case for expression={}, type(expression)={}".format(
                expression, type(expression)))

    @staticmethod
    def _parse_time_range(qualifier):
        time_range = []
        compile_timestamp_regex = re.compile(START_STOP_PATTERN)
        transformer = TimestampToUTC()
        for each_match in compile_timestamp_regex.finditer(qualifier):
            time_range.append(transformer.transform(each_match.group()))
        return " TO ".join(time_range)

    # @staticmethod
    # def remove_unwanted_space(format_string):
    #     compiled_exp = re.compile('\n\s{2,}')
    #     return compiled_exp.sub('', format_string)

    @staticmethod
    def _parse_mapped_fields(expression, value, comparator, mapped_fields_array, relevance_map_dict):
        comparison_string = ""
        mapped_fields_count = len(mapped_fields_array)
        for mapped_field in mapped_fields_array:
            # if expression.comparator == ComparisonComparators.NotEqual:
            #     comparison_string += "{mapped_field} {comparator} {value}".format(
            #         mapped_field=mapped_field, comparator=comparator, value=value)
            if expression.comparator == ComparisonComparators.GreaterThan or \
                    expression.comparator == ComparisonComparators.LessThan or \
                    expression.comparator == ComparisonComparators.GreaterThanOrEqual or \
                    expression.comparator == ComparisonComparators.LessThanOrEqual:
                # Check whether value is in datetime format, Ex: process.created
                pattern = "^\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z$"
                try:
                    match = bool(re.search(pattern, value))
                except:
                    match = False
                if match:
                    # IF value is in datetime format then do conversion of datetime into
                    # proper Range query of timestamps supported by elastic_ecs for comparators like :<,:>,:<=,:>=
                    comparison_string += _get_timestamp(mapped_field, comparator, value)
                else:
                    comparison_string += "{mapped_field}{comparator}{value}".format(mapped_field=mapped_field,
                                                                                    comparator=comparator,
                                                                                    value=value)
            # elif expression.comparator == ComparisonComparators.IsSubSet:
            #     comparison_string += "({mapped_field} {comparator} {value} AND {mapped_field}:*)".format(
            #         mapped_field=mapped_field, comparator=comparator, value=value)
            else:
                #self.get_format_string_from_property_json(mapped_field, relevance_map_dict)
                if mapped_field in relevance_map_dict.get('property'):
                    comparison_string = relevance_map_dict.get('property_format_string_mapping').\
                        get(relevance_map_dict.get('property').get(mapped_field)).format(
                        mapped_field=mapped_field, comparator=comparator, value=value)
                    # comparison_string = '{mapped_field} of it as lowercase {comparator} {value} as lowercase'.format(
                    #     mapped_field=mapped_field, comparator=comparator, value=value)
                else:
                    comparison_string = ''
            if mapped_fields_count > 1:
                comparison_string += " OR "
                mapped_fields_count -= 1

        return comparison_string

    @staticmethod
    def clean_format_string(format_string):
        return re.sub('\r|\n|\s{2,}|\t', ' ', format_string)

    # def _parse_expression(self, expression, qualifier=None):
    #     if isinstance(expression, ComparisonExpression):  # Base Case
    #          # Resolve STIX Object Path to a field in the target Data Model
    #         stix_object, stix_remainings = expression.object_path.split(':')
    #         # Added newly
    #         mapped_fields_array = self.dmm.map_field(stix_object, stix_remainings)
    #         value = self._escape_value(expression.value)
    #         comparator = self.comparator_lookup[expression.comparator]
    #         # final_value = comparator + ' "' + value + '"'
    #         # stix_property = ""
    #         # stix_key = ""
    #         # self.query_type = stix_object
    #
    #         if '.' in stix_remainings:
    #             stix_property_and_key = stix_remainings.split('.')
    #             stix_property = stix_property_and_key[0]
    #             stix_key = stix_property_and_key[1]
    #
    #         if stix_remainings == 'parent_directory_ref.path':
    #             reference_property = 'folder'
    #             self.query_string.update({reference_property: value})
    #         else:
    #             if stix_key != "":
    #                 reference_property = stix_key
    #                 self.query_string.update({stix_property: stix_key})
    #                 self.query_string.update({'value': final_value})
    #             else:
    #                 self.query_string.update({stix_object: final_value})
    #
    #         self.query_string.update({'comparator': comparator})
    #
    #         return self.query_string
    #     elif isinstance(expression, CombinedComparisonExpression):
    #         self._parse_expression(expression.expr1)
    #         expression_operator = self.comparator_lookup[expression.operator]
    #         self._parse_expression(expression.expr2)
    #
    #         self.query_string.update({'expression_operator': expression_operator})
    #
    #         if qualifier is not None:
    #             logger.info("Qualifier is not supported in BigFix relevance query.")
    #
    #         return self.query_string
    #     elif isinstance(expression, ObservationExpression):
    #         return self._parse_expression(expression.comparison_expression, qualifier)
    #     elif isinstance(expression, Pattern):
    #         return self._parse_expression(expression.expression)
    #     else:
    #         raise RuntimeError("Unknown Recursion Case for expression={}, type(expression)={}".format(
    #             expression, type(expression)))

    def parse_expression(self, pattern: Pattern):
        return self._parse_expression(pattern)


def translate_pattern(pattern: Pattern, data_model_mapper, options):
    result_limit = options['result_limit']
    # timerange = options['timerange']
    list_final_query = []
    translated_dictionary = RelevanceQueryStringPatternTranslator(pattern, data_model_mapper, result_limit)
    final_query = translated_dictionary.qualified_queries

    # TO BE COMMENTED OUT FOR NOW
    # AS WE HAVE INCORPORATED THE CHANGE WITH _PARSE_MAPPED_FIELDS METHOD
    # format_type = ""
    # final_query = ""
    # name_object = 'name'
    # process_object = 'process'
    # file_object = 'file'
    # hash_object = 'hashes'
    # value_object = 'value'
    # directory_alias = 'folder'
    #
    # if hash_object in query_dictionary:
    #     hash_type = query_dictionary.get(hash_object)
    #     if '-' in hash_type:
    #         hash_type = hash_type.replace('-', '').lower()
    #
    # if file_object in query_dictionary:
    #     if file_object in query_dictionary and hash_object in query_dictionary and directory_alias in query_dictionary:
    #         file_name = query_dictionary.get(file_object)
    #         path_value = query_dictionary.get(directory_alias)
    #         hash_value = query_dictionary.get(value_object)
    #         format_type = 'file_name_with_hash'
    #         final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type).format(name_object=name_object, file_name=file_name,
    #                                                                                                  expression_operator=query_dictionary.get('expression_operator'), hash_type=hash_type, hash_value=hash_value, file_path=path_value)
    #     elif hash_object in query_dictionary and directory_alias in query_dictionary:
    #         path_value = query_dictionary.get(directory_alias)
    #         hash_value = query_dictionary.get(value_object)
    #         format_type = 'file_query'
    #         final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type).format(stix_object=hash_type, object_value=hash_value, file_path=path_value)
    #     elif hash_object not in query_dictionary:
    #         file_name = query_dictionary.get(file_object)
    #         path_value = query_dictionary.get(directory_alias)
    #         if "*" not in file_name:
    #             format_type = 'file_query'
    #             final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type).format(stix_object=name_object, object_value=file_name, file_path=path_value)
    #         else:
    #             format_type = 'all_files_in_directory'
    #             final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type).format(file_path=path_value)
    # elif process_object in query_dictionary:
    #     process_name = query_dictionary.get(process_object)
    #     if hash_object not in query_dictionary:
    #         if "*" not in process_name:
    #             format_type = 'filter_processes_with_name'
    #             final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type).format(process_object=name_object, process_name=process_name)
    #         else:
    #             format_type = 'all_processes'
    #             final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type)
    #     else:
    #         hash_value = query_dictionary.get(value_object)
    #         format_type = 'process_name_with_hash'
    #         final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type).format(process_object=name_object, process_name=process_name,
    #                                                                                                  expression_operator=query_dictionary.get('expression_operator'), hash_type=hash_type, hash_value=hash_value)
    # elif hash_object in query_dictionary and directory_alias in query_dictionary:
    #     path_value = query_dictionary.get(directory_alias)
    #     hash_value = query_dictionary.get(value_object)
    #     format_type = 'file_query'
    #     final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type).format(stix_object=hash_type, object_value=hash_value, file_path=path_value)
    # elif hash_object in query_dictionary:
    #     hash_value = query_dictionary.get(value_object)
    #     format_type = 'process_hash_query'
    #     final_query = RelevanceQueryStringPatternTranslator.query_format.get(format_type).format(hash_type=hash_type, hash_value=hash_value)
    # else:
    #     logger.info('Unable to translate the Stix pattern into Relevance query')
    #
    #     return 'Unable to translate the Stix pattern into Relevance query'
    final_query = " ".join(final_query)
    compile_obs_split_regex = re.compile('\${4}\w{2,3}\#{4}')
    for each_query in compile_obs_split_regex.split(final_query):
        print (each_query)
        besapi_query = '<BESAPI xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"BESAPI.xsd\"><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>' + \
        each_query + '</QueryText><Target><CustomRelevance>true</CustomRelevance></Target></ClientQuery></BESAPI>'
        list_final_query.append(besapi_query)

    # Clearing out the query dictionary as we no longer need.
    RelevanceQueryStringPatternTranslator.query_string.clear()
    return list_final_query


def _format_translated_queries(query_array):
    # remove empty strings in the array
    query_array = list(map(lambda x: x.strip(), list(filter(None, query_array))))

    formatted_queries = []
    for query in query_array:
        if _test_START_STOP_format(query):
            # Remove leading 't' before timestamps
            query = re.sub("(?<=START)t|(?<=STOP)t", "", query)
            # Split individual query to isolate timestamps
            query_parts = re.split("(START)|(STOP)", query)
            # Remove None array entries
            query_parts = list(map(lambda x: x.strip(), list(filter(None, query_parts))))
            if len(query_parts) == 5:
                formatted_queries.append(_convert_timestamps_to_milliseconds(query_parts))
            else:
                logger.info("Omitting query due to bad format for START STOP qualifier timestamp")
                continue
        else:
            formatted_queries.append(query)
    return formatted_queries


def _test_START_STOP_format(query_string) -> bool:
    # Matches STARTt'1234-56-78T00:00:00.123Z'STOPt'1234-56-78T00:00:00.123Z'
    pattern = "START((t'\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z')|(\s\d{13}\s))STOP"
    match = re.search(pattern, query_string)
    return bool(match)


def _convert_timestamps_to_milliseconds(query_parts):
    # grab time stamps from array
    start_time = _test_or_add_milliseconds(query_parts[2])
    stop_time = _test_or_add_milliseconds(query_parts[4])
    return query_parts[0] + ' AND (@timestamp:["' + str(start_time) + '" TO "' + str(stop_time) + '"])'


def _test_or_add_milliseconds(timestamp) -> str:
    if not _test_timestamp(timestamp):
        raise ValueError("Invalid timestamp")
    # remove single quotes around timestamp
    timestamp = re.sub("'", "", timestamp)
    # check for 3-decimal milliseconds
    pattern = "\.\d+Z$"
    if not bool(re.search(pattern, timestamp)):
        timestamp = re.sub('Z$', '.000Z', timestamp)
    return timestamp


def _test_timestamp(timestamp) -> bool:
    pattern = "^'\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z'$"
    match = re.search(pattern, timestamp)
    return bool(match)
