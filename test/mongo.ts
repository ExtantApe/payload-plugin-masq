import { MongoMemoryReplSet } from 'mongodb-memory-server'

/**
 * A throwaway one-member MongoDB replica set for a test file: loopback only, no Unix socket, a port the
 * system picks and a data folder of its own, which `stop()` removes.
 */
export const startMongo = () =>
  MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger', ip: '127.0.0.1', args: ['--nounixsocket'] } })
