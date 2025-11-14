import * as crypto from './crypto.mjs';
import * as logger from './logger.mjs';
import { getCurrentTimestamp, deepClone, calculateAge } from './utils.mjs';
import { getBlockTemplate, getIdentityConfig } from './config.mjs';

export async function createBlock(data, ownerPublicKey, encryptionKey, ownerPrivateKey, prevHash = null) {
  const template = deepClone(getBlockTemplate());
  const encryptedData = crypto.encryptFields(data, encryptionKey);
  const block = {
    encryptedData,
    tokens: {},
    metadata: {
      ...template.metadata,
      createdAt: getCurrentTimestamp(),
      updatedAt: getCurrentTimestamp(),
      ownerPubKey: ownerPublicKey,
      lifecycleStage: 'genesis',
      deathDate: null,
      rotationsLeft: getIdentityConfig().maxKeyRotations
    },
    prevHash
  };
  block.hash = calculateBlockHash(block);
  const blockData = JSON.stringify({
    hash: block.hash,
    encryptedData: block.encryptedData,
    metadata: block.metadata,
    prevHash: block.prevHash
  });
  block.signature = crypto.signEd25519(blockData, ownerPrivateKey);
  logger.debug('Block created', { hash: block.hash });
  return block;
}

export function calculateBlockHash(block) {
  const hashData = JSON.stringify({
    encryptedData: block.encryptedData,
    tokens: block.tokens,
    metadata: {
      createdAt: block.metadata.createdAt,
      updatedAt: block.metadata.updatedAt,
      ownerPubKey: block.metadata.ownerPubKey,
      lifecycleStage: block.metadata.lifecycleStage,
      deathDate: block.metadata.deathDate,
      rotationsLeft: block.metadata.rotationsLeft
    },
    prevHash: block.prevHash
  });
  return crypto.sha512(hashData);
}

export function verifyBlockSignature(block) {
  if (!block || !block.signature || !block.metadata || !block.metadata.ownerPubKey) {
    return false;
  }
  const blockData = JSON.stringify({
    hash: block.hash,
    encryptedData: block.encryptedData,
    metadata: block.metadata,
    prevHash: block.prevHash
  });
  return crypto.verifyEd25519(blockData, block.signature, block.metadata.ownerPubKey);
}

export function verifyBlockHash(block) {
  const calculatedHash = calculateBlockHash(block);
  return calculatedHash === block.hash;
}

export function updateBlock(block, newData, encryptionKey, ownerPrivateKey) {
  const existingFields = Object.keys(block.encryptedData);
  const decryptedData = crypto.decryptFields(block.encryptedData, encryptionKey, existingFields);
  const mergedData = { ...decryptedData, ...newData };
  block.encryptedData = crypto.encryptFields(mergedData, encryptionKey);
  block.metadata.updatedAt = getCurrentTimestamp();
  block.hash = calculateBlockHash(block);
  const blockData = JSON.stringify({
    hash: block.hash,
    encryptedData: block.encryptedData,
    metadata: block.metadata,
    prevHash: block.prevHash
  });
  block.signature = crypto.signEd25519(blockData, ownerPrivateKey);
  logger.debug('Block updated', { hash: block.hash });
  return block;
}

export function rotateBlockKey(block, oldKey, newKey, newOwnerPublicKey, newOwnerPrivateKey, newStage) {
  if (block.metadata.rotationsLeft <= 0) {
    throw new Error('No rotations left');
  }
  const fields = Object.keys(block.encryptedData);
  const decryptedData = crypto.decryptFields(block.encryptedData, oldKey, fields);
  block.encryptedData = crypto.encryptFields(decryptedData, newKey);
  block.metadata.ownerPubKey = newOwnerPublicKey;
  block.metadata.lifecycleStage = newStage;
  block.metadata.rotationsLeft--;
  block.metadata.updatedAt = getCurrentTimestamp();
  block.hash = calculateBlockHash(block);
  const blockData = JSON.stringify({
    hash: block.hash,
    encryptedData: block.encryptedData,
    metadata: block.metadata,
    prevHash: block.prevHash
  });
  block.signature = crypto.signEd25519(blockData, newOwnerPrivateKey);
  logger.info('Block key rotated', { hash: block.hash, newStage });
  return block;
}

export function checkLifecycleTransition(block, encryptionKey) {
  const lifecycle = getIdentityConfig().lifecycle;
  const currentStage = block.metadata.lifecycleStage;
  if (currentStage === 'expired') {
    return { eligible: false, reason: 'Block already expired' };
  }
  let age = 0;
  try {
    const decrypted = crypto.decryptFields(block.encryptedData, encryptionKey, ['dob']);
    age = calculateAge(decrypted.dob);
  } catch (error) {
    return { eligible: false, reason: 'Cannot decrypt DOB' };
  }
  if (currentStage === 'genesis' && age >= lifecycle.guardianAge) {
    return { eligible: true, nextStage: 'guardian' };
  }
  if (currentStage === 'guardian' && age >= lifecycle.selfAge) {
    return { eligible: true, nextStage: 'self' };
  }
  return { eligible: false, reason: 'Not eligible for transition' };
}

export function markAsDeceased(block, ownerPrivateKey) {
  block.metadata.deathDate = getCurrentTimestamp();
  block.metadata.updatedAt = getCurrentTimestamp();
  block.hash = calculateBlockHash(block);
  const blockData = JSON.stringify({
    hash: block.hash,
    encryptedData: block.encryptedData,
    metadata: block.metadata,
    prevHash: block.prevHash
  });
  block.signature = crypto.signEd25519(blockData, ownerPrivateKey);
  logger.info('Block marked as deceased', { hash: block.hash });
  return block;
}

export function shouldPruneBlock(block) {
  if (!block.metadata.deathDate) {
    return false;
  }
  const lifecycle = getIdentityConfig().lifecycle;
  const graceSeconds = lifecycle.deceasedGraceYears * 365 * 24 * 60 * 60;
  const currentTime = getCurrentTimestamp();
  return (currentTime - block.metadata.deathDate) > graceSeconds;
}

export function updateLifecycleStage(block, newStage) {
  block.metadata.lifecycleStage = newStage;
  block.metadata.updatedAt = getCurrentTimestamp();
}

export default {
  createBlock,
  calculateBlockHash,
  verifyBlockSignature,
  verifyBlockHash,
  updateBlock,
  rotateBlockKey,
  checkLifecycleTransition,
  markAsDeceased,
  shouldPruneBlock,
  updateLifecycleStage
};
