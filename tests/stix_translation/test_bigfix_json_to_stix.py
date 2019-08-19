from stix_shifter.stix_translation.src.json_to_stix import json_to_stix_translator
from stix_shifter.stix_translation.src.utils import transformers
from stix_shifter.stix_translation.src.modules.bigfix import bigfix_translator
from stix_shifter.stix_translation import stix_translation

import json
import unittest

interface = bigfix_translator.Translator()
map_file = open(interface.mapping_filepath).read()

map_data = json.loads(map_file)

data_source = {
    "type": "identity",
    "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "name": "bigfix",
    "identity_class": "events"
}

options = {}

one_file = {
            "computer_identity": "1617245870-voyager01.hcl.local",
            "subQueryID": 1,
            "type": "file",
            "file_name": "anaconda-ks.cfg",
            "sha256hash": "f706afb5b9ef9b4e8de5aa3b3f850e9bb698e8eec74d96e0522d8623e7202637",
            "sha1hash": "b2f10095ef4710b92b16166c790cf5966033d183",
            "md5hash": "992edb0e3a0ba9e40709a62c7987e079",
            "file_path": "/root/anaconda-ks.cfg",
            "modified_time": "1528208223"
}

multi_file = [
        {
            "computer_identity": "1617245870-voyager01.hcl.local",
            "subQueryID": 1,
            "type": "file",
            "file_name": "anaconda-ks.cfg",
            "sha256hash": "f706afb5b9ef9b4e8de5aa3b3f850e9bb698e8eec74d96e0522d8623e7202637",
            "sha1hash": "b2f10095ef4710b92b16166c790cf5966033d183",
            "md5hash": "992edb0e3a0ba9e40709a62c7987e079",
            "file_path": "/root/anaconda-ks.cfg",
            "modified_time": "1528208223"
        },
        {
            "computer_identity": "1617245870-voyager01.hcl.local",
            "subQueryID": 1,
            "type": "file",
            "file_name": "anaconda-ks.cfg",
            "sha256hash": "f706afb5b9ef9b4e8de5aa3b3f850e9bb698e8eec74d96e0522d8623e7202637",
            "sha1hash": "b2f10095ef4710b92b16166c790cf5966033d183",
            "md5hash": "992edb0e3a0ba9e40709a62c7987e079",
            "file_path": "/root/anaconda-ks.cfg",
            "modified_time": "1528208223"
        }
]

one_process = {
        "computer_identity": "541866979-suse01",
        "subQueryID": 1,
        "start_time": "1559997049",
        "type": "process",
        "process_name": "systemd",
        "process_id": "1",
        "sha256hash": "9b8f3d4540b117cfbda73ba8ad75a953bcdfdb13ab7ebff6e69ebb35c2c7796f",
        "sha1hash": "4451aafaeb5d6a4a141789c3f4713c7da908f969",
        "md5hash": "47b7a75ad014f8dc81810731408a6073",
        "file_path": "/usr/lib/systemd/systemd"
    }


multi_process = [
    {
        "computer_identity": "541866979-suse01",
        "subQueryID": 1,
        "start_time": "1559997049",
        "type": "process",
        "process_name": "systemd",
        "process_id": "1",
        "sha256hash": "9b8f3d4540b117cfbda73ba8ad75a953bcdfdb13ab7ebff6e69ebb35c2c7796f",
        "sha1hash": "4451aafaeb5d6a4a141789c3f4713c7da908f969",
        "md5hash": "47b7a75ad014f8dc81810731408a6073",
        "file_path": "/usr/lib/systemd/systemd"
    },
    {
        "computer_identity": "537366757-farpoint.hcl.local",
        "subQueryID": 1,
        "start_time": "1559567760",
        "type": "process",
        "process_name": "systemd",
        "process_id": "1",
        "sha256hash": "003c6d3848e64a05507e716f0808dfaf2dba53766c2df599ab5ea6cc6c8d2936",
        "sha1hash": "27a3ca408fdebf94d97c4e158d48ee50af98b43d",
        "md5hash": "c5d05bbc14eca6af0b517c35f48ff350",
        "file_path": "/usr/lib/systemd/systemd"
    }
]




class TestBigFixTransform(unittest.TestCase, object):
    @staticmethod
    def get_first(itr, constraint):
        return next(
            (obj for obj in itr if constraint(obj)),
            None
        )

    @staticmethod
    def get_first_of_type(itr, typ):
        return TestBigFixTransform.get_first(itr, lambda o: type(o) == dict and o.get('type') == typ)

    def test_common_prop(self):
        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [one_file], transformers.get_all_transformers(), options)
        assert (result_bundle['type'] == 'bundle')
        result_bundle_objects = result_bundle['objects']

        result_bundle_identity = result_bundle_objects[0]
        assert (result_bundle_identity['type'] == data_source['type'])
        assert (result_bundle_identity['id'] == data_source['id'])
        assert (result_bundle_identity['name'] == data_source['name'])
        assert (result_bundle_identity['identity_class']
                == data_source['identity_class'])

        observed_data = result_bundle_objects[1]

        assert (observed_data['id'] is not None)
        assert (observed_data['type'] == "observed-data")
        assert (observed_data['created_by_ref'] == result_bundle_identity['id'])

    def test_custom_mapping(self):
        data_source_string = json.dumps(data_source)
        data = [{
            "custompayload": "SomeBase64Payload",
            "url": "www.example.com",
            "filename": "somefile.exe",
            "username": "someuserid2018"
        }]
        data_string = json.dumps(data)

        options = {"mapping": {
            "username": {"key": "user-account.user_id"},
            "url": {"key": "url.value"},
            "custompayload": {"key": "artifact.payload_bin"}
        }}

        translation = stix_translation.StixTranslation()
        result = translation.translate('bigfix', 'results', data_source_string, data_string, options)
        result_bundle = json.loads(result)
        print(result_bundle)

        result_bundle_objects = result_bundle['objects']
        observed_data = result_bundle_objects[1]

        assert ('objects' in observed_data)
        objects = observed_data['objects']

        file_object = TestBigFixTransform.get_first_of_type(objects.values(), 'file')
        assert (file_object is None), 'default file object type was returned even though it was not included in the custom mapping'

        curr_obj = TestBigFixTransform.get_first_of_type(objects.values(), 'artifact')
        assert (curr_obj is not None), 'artifact object type not found'
        assert (curr_obj.keys() == {'type', 'payload_bin'})
        assert (curr_obj['payload_bin'] == "SomeBase64Payload")

    def test_one_file_prop(self):
        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [one_file], transformers.get_all_transformers(), options)
        assert (result_bundle['type'] == 'bundle')

        result_bundle_objects = result_bundle['objects']
        observed_data = result_bundle_objects[1]

        assert ('objects' in observed_data)
        objects = observed_data['objects']
        print(objects)
        print('*' * 100)
        print(objects.values())

        nt_object = TestBigFixTransform.get_first_of_type(objects.values(), 'file')
        print(nt_object.keys())
        print(nt_object.values())
        assert (nt_object is not None), 'file object type not found'
        assert (nt_object.keys() ==
                {'type', 'name', 'hashes', 'parent_directory_ref'})
        assert (nt_object['type'] == 'file')
        assert (nt_object['name'] == 'anaconda-ks.cfg')
        assert (nt_object['hashes'] == {'SHA-256': 'f706afb5b9ef9b4e8de5aa3b3f850e9bb698e8eec74d96e0522d8623e7202637',
                                        'SHA-1': 'b2f10095ef4710b92b16166c790cf5966033d183',
                                        'MD5': '992edb0e3a0ba9e40709a62c7987e079'})
        assert (nt_object['parent_directory_ref'] == '1')


    def test_multi_file_prop(self):
        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, multi_file, transformers.get_all_transformers(), options)
        assert (result_bundle['type'] == 'bundle')

        result_bundle_objects = result_bundle['objects']
        observed_data = result_bundle_objects[1]

        assert ('objects' in observed_data)
        objects = observed_data['objects']
        print(objects)
        print('*' * 100)
        print(objects.values())

        nt_object = TestBigFixTransform.get_first_of_type(objects.values(), 'file')
        print(nt_object.keys())
        print(nt_object.values())
        assert (nt_object is not None), 'file object type not found'
        assert (nt_object.keys() ==
                {'type', 'name', 'hashes', 'parent_directory_ref'})
        assert (nt_object['type'] == 'file')
        assert (nt_object['name'] == 'anaconda-ks.cfg')
        assert (nt_object['hashes'] == {'SHA-256': 'f706afb5b9ef9b4e8de5aa3b3f850e9bb698e8eec74d96e0522d8623e7202637',
                                        'SHA-1': 'b2f10095ef4710b92b16166c790cf5966033d183',
                                        'MD5': '992edb0e3a0ba9e40709a62c7987e079'})
        assert (nt_object['parent_directory_ref'] == '1')

    def test_one_process_prop(self):
        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [one_process], transformers.get_all_transformers(), options)
        assert (result_bundle['type'] == 'bundle')

        result_bundle_objects = result_bundle['objects']
        observed_data = result_bundle_objects[1]

        assert ('objects' in observed_data)
        objects = observed_data['objects']
        print(objects)
        print('*' * 100)
        print(objects.values())

        nt_object = TestBigFixTransform.get_first_of_type(objects.values(), 'process')
        print(nt_object.keys())
        print(nt_object.values())
        assert (nt_object is not None), 'file object type not found'
        assert (nt_object.keys() ==
                {'type', 'name', 'pid', 'binary_ref'})
        assert (nt_object['type'] == 'process')
        assert (nt_object['name'] == 'systemd')
        assert (nt_object['pid'] == '1')
        assert (nt_object['binary_ref'] == '1')

    def test_multi_process_prop(self):
        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, multi_process, transformers.get_all_transformers(), options)
        assert (result_bundle['type'] == 'bundle')

        result_bundle_objects = result_bundle['objects']
        observed_data = result_bundle_objects[1]

        assert ('objects' in observed_data)
        objects = observed_data['objects']
        print(objects)
        print('*' * 100)
        print(objects.values())

        nt_object = TestBigFixTransform.get_first_of_type(objects.values(), 'process')
        print(nt_object.keys())
        print(nt_object.values())
        assert (nt_object is not None), 'file object type not found'
        assert (nt_object.keys() ==
                {'type', 'name', 'pid', 'binary_ref'})
        assert (nt_object['type'] == 'process')
        assert (nt_object['name'] == 'systemd')
        assert (nt_object['pid'] == '1')
        assert (nt_object['binary_ref'] == '1')
