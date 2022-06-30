import sys
import traceback

import click

from modules.core.output import console
from modules.spray import helpers, spray


class SprayExceptionWrapper(click.Command):
    def invoke(self, ctx: click.Context):
        try:
            return super(SprayExceptionWrapper, self).invoke(ctx)
        except (KeyboardInterrupt, Exception) as e:
            if isinstance(e, KeyboardInterrupt):
                sys.stdout.write("\b\b\r")
                sys.stdout.flush()
                console.print_info("Received keyboard interrupt")
            else:
                if sys.exc_info()[0]:
                    print("An exception was raised: %s" % sys.exc_info()[0].__name__)
                else:
                    print("An unknown exception was raised: %s" % sys.exc_info())
                print("Stack trace from most recent exception:")
                traceback.print_exc()
            helpers.export_auth_results(spray.auth_results)
            sys.exit(1)
