/** First trusted step of every privileged job: right repository, right branch, current tip. */
import { assertReleaseTip, runContextFrom, status } from './github.ts';
import { checkJobEnv, requireEnv } from './job-env.ts';

try {
  checkJobEnv('release-tip', process.env);
  await assertReleaseTip(runContextFrom(process.env), requireEnv(process.env, 'GH_TOKEN'));
  status('FE_RELEASE_TIP=OK');
} catch (error) {
  console.error(`FE_RELEASE_TIP=FAIL ${error instanceof Error ? error.message : 'error'}`);
  process.exit(1);
}
