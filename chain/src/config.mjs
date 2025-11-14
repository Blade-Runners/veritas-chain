import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import * as logger from './logger.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

let config = null;

export async function loadConfig() {
  if (config) {
    return config;
  }
  try {
    const configPath = join(__dirname, '..', 'config.json');
    const data = await readFile(configPath, 'utf8');
    config = JSON.parse(data);
    validateConfig(config);
    logger.info('Configuration loaded successfully');
    return config;
  } catch (error) {
    logger.error('Failed to load configuration', error.message);
    throw error;
  }
}

function validateConfig(cfg) {
  const required = [
    'network',
    'security',
    'identity',
    'consensus',
    'blockTemplate',
    'genesisTemplate',
    'storage'
  ];
  for (const key of required) {
    if (!cfg[key]) {
      throw new Error(`Missing required configuration section: ${key}`);
    }
  }
  if (!cfg.network.httpPort || !cfg.network.p2pPort) {
    throw new Error('Missing required network ports');
  }
  const allowedAlgorithms = ['sha512', 'ed25519', 'aes-256-gcm'];
  if (!allowedAlgorithms.includes(cfg.security.hashAlgorithm)) {
    throw new Error('Invalid hash algorithm');
  }
  if (!allowedAlgorithms.includes(cfg.security.asymmetric)) {
    throw new Error('Invalid asymmetric encryption');
  }
  if (!allowedAlgorithms.includes(cfg.security.encryption)) {
    throw new Error('Invalid symmetric encryption');
  }
  if (!cfg.identity.lifecycle || 
      !cfg.identity.lifecycle.guardianAge || 
      !cfg.identity.lifecycle.selfAge) {
    throw new Error('Invalid identity lifecycle configuration');
  }
  if (!cfg.consensus.requiredSignatures) {
    throw new Error('Missing required signatures configuration');
  }
}

export function getConfig() {
  if (!config) {
    throw new Error('Configuration not loaded. Call loadConfig() first.');
  }
  return config;
}

export function getNetworkConfig() {
  return getConfig().network;
}

export function getSecurityConfig() {
  return getConfig().security;
}

export function getIdentityConfig() {
  return getConfig().identity;
}

export function getConsensusConfig() {
  return getConfig().consensus;
}

export function getStorageConfig() {
  return getConfig().storage;
}

export function getBlockTemplate() {
  return getConfig().blockTemplate;
}

export function getGenesisTemplate() {
  return getConfig().genesisTemplate;
}

export function getProtocolConfig() {
  if (!config.protocol) {
    throw new Error('Protocol configuration missing');
  }
  if (typeof config.protocol.internalSegmentSize !== 'number' || config.protocol.internalSegmentSize < 1) {
    throw new Error('protocol.internalSegmentSize must be a positive number');
  }
  if (typeof config.protocol.internalOffsetBounds !== 'number' || config.protocol.internalOffsetBounds < 1) {
    throw new Error('protocol.internalOffsetBounds must be a positive number');
  }
  return config.protocol;
}

export default {
  loadConfig,
  getConfig,
  getNetworkConfig,
  getSecurityConfig,
  getIdentityConfig,
  getConsensusConfig,
  getStorageConfig,
  getBlockTemplate,
  getGenesisTemplate,
  getProtocolConfig
};
