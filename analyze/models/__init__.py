import importlib


def create_model(version, segment_size):
    """ dynamically imports a version-specific model module and creates a model. """
    module = importlib.import_module('.v{}'.format(version), package='models')
    return module.create_model(segment_size)
