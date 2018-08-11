from flowbeat import BaseTest

import os


class Test(BaseTest):

    def test_base(self):
        """
        Basic test with exiting Flowbeat normally
        """
        self.render_config_template(
            path=os.path.abspath(self.working_dir) + "/log/*"
        )

        flowbeat_proc = self.start_beat()
        self.wait_until(lambda: self.log_contains("flowbeat is running"))
        exit_code = flowbeat_proc.kill_and_wait()
        assert exit_code == 0
