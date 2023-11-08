# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from collections import OrderedDict

from FTB.ProgramConfiguration import ProgramConfiguration

from guided_fuzzing_daemon.utils import create_envs


def test_create_envs(mocker):
    orig_env = {
        "global": "glval",
    }
    base_cfg = mocker.Mock(spec=ProgramConfiguration, env={})
    created_cfgs = []

    def new_cfg(orig_cfg):
        result = mocker.Mock(spec=ProgramConfiguration, env=orig_cfg.env.copy())
        created_cfgs.append(result)
        return result

    copy = mocker.patch("guided_fuzzing_daemon.utils.copy", side_effect=new_cfg)
    rnd = mocker.patch(
        "guided_fuzzing_daemon.utils.uniform",
        side_effect=(0.5, 60.0, 60.0, 25.0, 6.0, 0.0),
    )
    args = mocker.Mock()
    args.env = {"var1": "val1", "var2": "val2a"}
    # use OrderedDict to ensure calls to uniform above line up with var2/var3 order
    args.env_percent = OrderedDict(
        var2=OrderedDict(val2b=1.0, val2c=5.0),
        var3={"val3": 50.0},
    )
    envs, cfgs = create_envs(orig_env, args, 3, base_cfg)
    assert rnd.call_count == 6
    assert len(envs) == 3
    assert len(cfgs) == 3
    assert len(orig_env) == 1
    assert envs[0] == {
        "global": "glval",
        "var1": "val1",
        "var2": "val2b",
    }
    assert envs[1] == {
        "global": "glval",
        "var1": "val1",
        "var2": "val2a",
        "var3": "val3",
    }
    assert envs[2] == {
        "global": "glval",
        "var1": "val1",
        "var2": "val2c",
        "var3": "val3",
    }
    assert copy.call_count == 4
    assert created_cfgs[0].addEnvironmentVariables.call_args_list == [
        mocker.call({"var1": "val1", "var2": "val2a"}),
    ]
    assert cfgs[0].addEnvironmentVariables.call_args_list == [
        mocker.call({"var2": "val2b"})
    ]
    assert cfgs[1].addEnvironmentVariables.call_args_list == [
        mocker.call({"var3": "val3"})
    ]
    assert cfgs[2].addEnvironmentVariables.call_args_list == [
        mocker.call({"var2": "val2c", "var3": "val3"})
    ]
