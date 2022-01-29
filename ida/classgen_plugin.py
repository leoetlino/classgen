from abc import ABC, abstractmethod

from classgen_json import RecordInfo


class Plugin(ABC):
    """
    Example of a plugin that just leaves every record type untouched:

    .. code-block:: python
        class IdentityTransformPlugin(Plugin):
            def transform_record_data(self, name: str, data: RecordInfo) -> RecordInfo:
                return data

            def make_plugin(idb_path: str):
                return IdentityTransformPlugin()
    """

    @abstractmethod
    def transform_record_data(self, name: str, data: RecordInfo) -> RecordInfo:
        return data
