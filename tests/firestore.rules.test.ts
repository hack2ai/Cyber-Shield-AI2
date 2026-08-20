import { afterAll, beforeAll, beforeEach, describe, it } from 'vitest';
import {
  assertFails,
  assertSucceeds,
  initializeTestEnvironment,
  type RulesTestEnvironment,
} from '@firebase/rules-unit-testing';
import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
  type Firestore,
} from 'firebase/firestore';
import fs from 'node:fs';

const PROJECT_ID = 'demo-cyber-shield';
let testEnv: RulesTestEnvironment | undefined;
const rules = fs.readFileSync('firestore.rules', 'utf8');

function db(userId?: string): Firestore {
  if (!testEnv) throw new Error('Firestore emulator test environment is not initialized');
  return userId ? testEnv.authenticatedContext(userId).firestore() : testEnv.unauthenticatedContext().firestore();
}

beforeAll(async () => {
  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: { rules },
  });
});

beforeEach(async () => {
  await testEnv?.clearFirestore();
});

afterAll(async () => {
  await testEnv?.cleanup();
});

describe('Firestore authorization rules', () => {
  it('allows a signed-in user to create and read only their own profile', async () => {
    const userDb = db('alice');
    const userRef = doc(userDb, 'users/alice');
    await assertSucceeds(setDoc(userRef, {
      uid: 'alice', email: 'alice@example.com', role: 'user', createdAt: serverTimestamp(), displayName: 'Alice',
    }));
    await assertSucceeds(getDoc(userRef));
    await assertFails(getDoc(doc(db('bob'), 'users/alice')));
  });

  it('prevents role escalation while allowing safe profile edits', async () => {
    const userRef = doc(db('alice'), 'users/alice');
    await assertSucceeds(setDoc(userRef, {
      uid: 'alice', email: 'alice@example.com', role: 'user', createdAt: serverTimestamp(), displayName: 'Alice',
    }));
    await assertSucceeds(updateDoc(userRef, { displayName: 'Alice Smith' }));
    await assertFails(updateDoc(userRef, { role: 'admin' }));
  });

  it('rejects anonymous writes and cross-user report access', async () => {
    const ownerDb = db('alice');
    const reportRef = doc(ownerDb, 'scanReports/report-1');
    const report = {
      userId: 'alice', target: 'example.com', classification: 'Safe', threatScore: 10, createdAt: serverTimestamp(),
    };
    await assertSucceeds(setDoc(reportRef, report));
    await assertFails(setDoc(doc(db(), 'scanReports/report-anon'), report));
    await assertSucceeds(getDoc(reportRef));
    await assertFails(getDoc(doc(db('bob'), 'scanReports/report-1')));
  });

  it('enforces report score bounds and immutability', async () => {
    const userDb = db('alice');
    await assertFails(setDoc(doc(userDb, 'scanReports/report-invalid'), {
      userId: 'alice', target: 'example.com', classification: 'Suspicious', threatScore: 101, createdAt: serverTimestamp(),
    }));
    const reportRef = doc(userDb, 'scanReports/report-valid');
    await assertSucceeds(setDoc(reportRef, {
      userId: 'alice', target: 'example.com', classification: 'Safe', threatScore: 10, createdAt: serverTimestamp(),
    }));
    await assertFails(updateDoc(reportRef, { threatScore: 90 }));
    await assertSucceeds(deleteDoc(reportRef));
  });

  it('allows owners to query only their reports', async () => {
    const aliceDb = db('alice');
    const bobDb = db('bob');
    await assertSucceeds(setDoc(doc(aliceDb, 'scanReports/alice-report'), {
      userId: 'alice', target: 'example.com', classification: 'Safe', createdAt: serverTimestamp(),
    }));
    await assertSucceeds(setDoc(doc(bobDb, 'scanReports/bob-report'), {
      userId: 'bob', target: 'example.org', classification: 'Safe', createdAt: serverTimestamp(),
    }));
    const ownQuery = query(collection(aliceDb, 'scanReports'), where('userId', '==', 'alice'));
    await assertSucceeds(getDocs(ownQuery));
    const otherQuery = query(collection(aliceDb, 'scanReports'), where('userId', '==', 'bob'));
    await assertFails(getDocs(otherQuery));
  });
});
