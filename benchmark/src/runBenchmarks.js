import 'babel-polyfill';
import { performance } from 'perf_hooks';
import * as fs from 'fs';

import pairingBenchmark from './primitives/pairing';
import randomBenchmark from './primitives/random';
import ElGamalKeygenBenchmark from './primitives/ElGamalKeygen';
import EntityKeygenBenchmark from './primitives/entityKeygen';
import CoinSigKeygenBenchmark from './primitives/CoinSigKeygen';
import NZKPCreationBenchmark from './primitives/NZKP_creation';
import NZKPVerificationBenchmark from './primitives/NZKP_verification';
import ElGamalEncryptionBenchmark from './primitives/ElGamalEncryption';
import ElGamalDecryptionBenchmark from './primitives/ElGamalDecryption';
import PublicKeyAggregation_2 from './primitives/PublicKeyAggregation_2';
import PublicKeyAggregation_5 from './primitives/PublicKeyAggregation_5';
import PublicKeyAggregation_10 from './primitives/PublicKeyAggregation_10';
import SignatureAggregation_2 from './primitives/SignatureAggregation_2';
import SignatureAggregation_5 from './primitives/SignatureAggregation_5';
import SignatureAggregation_10 from './primitives/SignatureAggregation_10';
import CoinSigning from './primitives/CoinSigning';
import coinVerification from './primitives/CoinSignVerification';
import ECDSA_Sign from './primitives/ECDSA_sig';
import ECDSA_Verify from './primitives/ECDSA_ver';
import SignatureRandomization from './primitives/SignatureRandomization';
import G1mul from './primitives/G1mul';
import G2mul from './primitives/G2mul';

const MAX_REPETITIONS = 10;

const doBenchmark = (benchmark) => {
  const prepResult = benchmark.prep();
  const timings = [];
  let runningTotal = 0;
  for (let i = 0; i < MAX_REPETITIONS + 2; i++) {
    console.log(`${benchmark.name}, iteration: ${i}`);
    const beforeEachResult = benchmark.beforeEach(...prepResult[1]);

    performance.mark(`start${benchmark.name}${i}`);
    const bench = benchmark.fn(...prepResult[0], ...beforeEachResult); // being measured
    performance.mark(`end${benchmark.name}${i}`);

    performance.measure(`timing${benchmark.name}${i}`, `start${benchmark.name}${i}`, `end${benchmark.name}${i}`);
    const measure = performance.getEntriesByName(`timing${benchmark.name}${i}`)[0];
    timings.push(measure.duration);
    runningTotal += measure.duration;
    performance.clearMarks();
    performance.clearMeasures();

    // if (runningTotal > MAX_TIME_PER_FUNCTION) {
    //   break;
    // }
  }
  // start by removing first two elements of the array due to them being considerably bigger because of JIT
  timings.shift();
  timings.shift();
  const writeString = timings.join('\n'); // more memory intensive but should not affect results
  // as now each write is written before new benchmark is started

  fs.writeFileSync(`results/${benchmark.name}_timing.txt`, writeString, () => {
    console.log(`${benchmark.name} results were written to a file`);
  });
};

// doBenchmark(pairingBenchmark);
// doBenchmark(randomBenchmark);
// doBenchmark(ElGamalKeygenBenchmark);
// doBenchmark(EntityKeygenBenchmark);
// doBenchmark(CoinSigKeygenBenchmark);
// doBenchmark(NZKPCreationBenchmark);
// doBenchmark(NZKPVerificationBenchmark);
// doBenchmark(ElGamalEncryptionBenchmark);
// doBenchmark(ElGamalDecryptionBenchmark);
// doBenchmark(PublicKeyAggregation_2);
// doBenchmark(PublicKeyAggregation_5);
// doBenchmark(PublicKeyAggregation_10);
// doBenchmark(SignatureAggregation_2);
// doBenchmark(SignatureAggregation_5);
// doBenchmark(SignatureAggregation_10);
// doBenchmark(CoinSigning);
// doBenchmark(coinVerification);
// doBenchmark(ECDSA_Sign);
// doBenchmark(ECDSA_Verify);
// doBenchmark(SignatureRandomization);
doBenchmark(G1mul);
doBenchmark(G2mul);
