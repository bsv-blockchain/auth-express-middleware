import { Request, Response, NextFunction } from 'express'
import fs from 'fs'
import mime from 'mime-types'
import {
  Utils,
  Wallet,
  VerifiableCertificate,
  Peer,
  AuthMessage,
  RequestedCertificateSet,
  Transport,
  SessionManager
} from '@bsv/sdk'

// Developers may optionally provide a handler for incoming certificates.
export interface AuthMiddlewareOptions {
  wallet: Wallet
  sessionManager?: SessionManager // Optional if dev wants custom SessionManager
  allowUnauthenticated?: boolean
  certificatesToRequest?: RequestedCertificateSet
  onCertificatesReceived?: (senderPublicKey: string, certs: VerifiableCertificate[], req: Request, res: Response, next: NextFunction) => void
}

export class ExpressTransport implements Transport {
  peer?: Peer
  allowAuthenticated: boolean
  openNonGeneralHandles: Record<string, Response[]> = {}
  openGeneralHandles: Record<string, Response> = {}
  openNextHandlers: Record<string, NextFunction> = {}

  private messageCallback?: (message: AuthMessage) => Promise<void>

  /**
   * Constructs a new ExpressTransport instance.
   * 
   * @param {boolean} [allowUnauthenticated=false] - Whether to allow unauthenticated requests passed the auth middleware. 
   *   If `true`, requests without authentication will be permitted, and `req.auth.identityKey` 
   *   will be set to `"unknown"`. If `false`, unauthenticated requests will result in a `401 Unauthorized` response.
   */
  constructor(allowUnauthenticated: boolean = false) {
    this.allowAuthenticated = allowUnauthenticated
  }

  setPeer(peer: Peer): void {
    this.peer = peer
  }

  /**
   * Sends an AuthMessage to the connected Peer.
   * This method uses an Express response object to deliver the message to the specified Peer. 
   * 
   * ### Parameters:
   * @param {AuthMessage} message - The authenticated message to send. 
   * 
   * ### Returns:
   * @returns {Promise<void>} A promise that resolves once the message has been sent successfully.
   */
  async send(message: AuthMessage): Promise<void> {
    if (message.messageType !== 'general') {
      const handles = this.openNonGeneralHandles[message.identityKey]
      if (!Array.isArray(handles) || handles.length === 0) {
        throw new Error('No open handles to this peer!')
      } else {
        // Since this is an initial response, we can assume there's only one handle per identity
        const res = handles[0]
        const responseHeaders: Record<string, string> = {}
        responseHeaders['x-bsv-auth-version'] = message.version
        responseHeaders['x-bsv-auth-message-type'] = message.messageType
        responseHeaders['x-bsv-auth-identity-key'] = message.identityKey
        responseHeaders['x-bsv-auth-nonce'] = message.nonce!
        responseHeaders['x-bsv-auth-your-nonce'] = message.yourNonce!
        responseHeaders['x-bsv-auth-signature'] = Utils.toHex(message.signature!)

        if (message.requestedCertificates) {
          responseHeaders['x-bsv-auth-requested-certificates'] = JSON.stringify(message.requestedCertificates)
        }
        if ((res as any).__set !== undefined) {
          this.resetRes(res)
        }
        for (const [k, v] of Object.entries(responseHeaders)) {
          res.set(k, v)
        }

        res.send(message)
        handles.shift()
      }
    } else {
      // General message
      const reader = new Utils.Reader(message.payload)
      const requestId = Utils.toBase64(reader.read(32))

      if (!this.openGeneralHandles[requestId]) {
        throw new Error('No response handle for this requestId!')
      }
      let res: Response = this.openGeneralHandles[requestId]
      delete this.openGeneralHandles[requestId]

      const statusCode = reader.readVarIntNum()
      res.__status(statusCode)

      const responseHeaders: Record<string, string> = {}
      const nHeaders = reader.readVarIntNum()
      if (nHeaders > 0) {
        for (let i = 0; i < nHeaders; i++) {
          const nHeaderKeyBytes = reader.readVarIntNum()
          const headerKeyBytes = reader.read(nHeaderKeyBytes)
          const headerKey = Utils.toUTF8(headerKeyBytes)
          const nHeaderValueBytes = reader.readVarIntNum()
          const headerValueBytes = reader.read(nHeaderValueBytes)
          const headerValue = Utils.toUTF8(headerValueBytes)
          responseHeaders[headerKey] = headerValue
        }
      }

      responseHeaders['x-bsv-auth-version'] = message.version
      responseHeaders['x-bsv-auth-identity-key'] = message.identityKey
      responseHeaders['x-bsv-auth-nonce'] = message.nonce!
      responseHeaders['x-bsv-auth-your-nonce'] = message.yourNonce!
      responseHeaders['x-bsv-auth-signature'] = Utils.toHex(message.signature!)
      responseHeaders['x-bsv-auth-request-id'] = requestId

      if (message.requestedCertificates) {
        responseHeaders['x-bsv-auth-requested-certificates'] = JSON.stringify(message.requestedCertificates)
      }

      for (const [k, v] of Object.entries(responseHeaders)) {
        res.__set(k, v)
      }

      let responseBody
      const responseBodyBytes = reader.readVarIntNum()
      if (responseBodyBytes > 0) {
        responseBody = reader.read(responseBodyBytes)
      }

      res = this.resetRes(res)
      if (responseBody) {
        res.send(Buffer.from(new Uint8Array(responseBody)))
      } else {
        res.end()
      }
    }
  }

  /**
   * Stores the callback bound by a Peer
   * @param callback 
   */
  async onData(callback: (message: AuthMessage) => Promise<void>): Promise<void> {
    // Just store the callback
    this.messageCallback = callback
  }

  /**
   * Handles an incoming request for the Express server.
   * 
   * This method processes both general and non-general message types, 
   * manages peer-to-peer certificate handling, and modifies the response object 
   * to enable custom behaviors like certificate requests and tailored responses.
   * 
   * ### Behavior:
   * - For `/.well-known/auth`:
   *   - Handles non-general messages and listens for certificates.
   *   - Calls the `onCertificatesReceived` callback (if provided) when certificates are received.
   * - For general messages:
   *   - Sets up a listener for peer-to-peer general messages.
   *   - Overrides response methods (`send`, `json`, etc.) for custom handling.
   * - Returns a 401 error if mutual authentication fails.
   * 
   * ### Parameters:
   * @param {Request} req - The incoming HTTP request.
   * @param {Response} res - The HTTP response.
   * @param {NextFunction} next - The Express `next` middleware function.
   * @param {Function} [onCertificatesReceived] - Optional callback invoked when certificates are received.
   */
  public handleIncomingRequest(req: Request, res: Response, next: NextFunction, onCertificatesReceived?: (senderPublicKey: string, certs: VerifiableCertificate[], req: Request, res: Response, next: NextFunction) => void): void {
    try {
      if (!this.peer) {
        throw new Error('You must set a Peer before you can handle incoming requests!')
      }
      if (req.path === '/.well-known/auth') {
        // Non-general message
        const message = req.body as AuthMessage

        // Get a the request id
        let requestId = req.headers['x-bsv-auth-request-id'] as string
        if (!requestId) {
          requestId = message.identityKey
        }

        if (this.openNonGeneralHandles[requestId]) {
          this.openNonGeneralHandles[requestId].push(res)
        } else {
          this.openNonGeneralHandles[requestId] = [res]
        }

        if (!this.peer.sessionManager.hasSession(message.identityKey)) {
          const listenerId = this.peer.listenForCertificatesReceived((senderPublicKey: string, certs: VerifiableCertificate[]) => {
            if (senderPublicKey !== req.body.identityKey) {
              return
            }
            // This is currently an internal response and never reaches the client...
            if (!certs || certs.length === 0) {
              // Will there ever be more then one pending certificateResponse?
              this.openNonGeneralHandles[senderPublicKey][0].status(400).json({ status: 'No certificates provided' })
            } else {
              this.openNonGeneralHandles[senderPublicKey][0].json({ status: 'certificate received' })
              if (onCertificatesReceived) {
                onCertificatesReceived(senderPublicKey, certs, req, res, next)
              }

              const nextFn = this.openNextHandlers[message.identityKey]
              if (nextFn) {
                nextFn()
                delete this.openNextHandlers[message.identityKey]
              }
            }

            this.openNonGeneralHandles[senderPublicKey].shift()
            // Note: do we ever stop listening for certificates?
          })
        }

        if (this.messageCallback) {
          this.messageCallback(message)
            .catch((err) => {
              console.error(err)
              return res.status(500).json({
                status: 'error',
                code: 'ERR_INTERNAL_SERVER_ERROR',
                description: err.message || 'An unknown error occurred.'
              })
            })
        }

      } else {
        // Possibly general message
        if (req.headers['x-bsv-auth-request-id']) {
          const message = buildAuthMessageFromRequest(req)

          // Setup general message listener
          const listenerId = this.peer.listenForGeneralMessages((senderPublicKey: string, payload: number[]) => {
            try {
              if (senderPublicKey !== req.headers['x-bsv-auth-identity-key']) return
              const requestId = Utils.toBase64(new Utils.Reader(payload).read(32))
              if (requestId === req.headers['x-bsv-auth-request-id']) {
                this.peer?.stopListeningForGeneralMessages(listenerId)
                req.auth = { identityKey: senderPublicKey }

                let responseStatus = 200
                let responseHeaders = {}
                let responseBody: number[] = []

                // Override methods
                res.__status = res.status
                res.status = n => {
                  responseStatus = n
                  return res // Return res for chaining
                }

                res.__set = res.set
                res.set = (keyOrHeaders, value) => {
                  if (typeof keyOrHeaders === 'object' && keyOrHeaders !== null) {
                    // Handle setting multiple headers with an object
                    for (const [key, val] of Object.entries(keyOrHeaders)) {
                      if (typeof key !== 'string') {
                        throw new TypeError(`Header name must be a string, received: ${typeof key}`)
                      }
                      responseHeaders[key.toLowerCase()] = String(val) // Ensure value is a string
                    }
                  } else if (typeof keyOrHeaders === 'string') {
                    // Handle setting a single header
                    if (typeof value === 'undefined') {
                      throw new TypeError('Value must be provided when setting a single header')
                    }
                    responseHeaders[keyOrHeaders.toLowerCase()] = String(value) // Ensure value is a string
                  } else {
                    throw new TypeError('Invalid arguments: res.set expects a string or an object')
                  }

                  return res // Return res for chaining
                }

                const buildResponse = async (): Promise<void> => {
                  const payload = buildResponsePayload(requestId, responseStatus, responseHeaders, responseBody, req)
                  this.openGeneralHandles[requestId] = res
                  await this.peer?.toPeer(payload, req.headers['x-bsv-auth-identity-key'])
                }

                res.__send = res.send
                res.send = (val: any) => {
                  // If the value is an object and no content-type is set, assume JSON
                  if (typeof val === 'object' && val !== null && !responseHeaders['content-type']) {
                    res.set('content-type', 'application/json')
                  }

                  responseBody = convertValueToArray(val, responseHeaders)
                  buildResponse()
                }

                res.__json = res.json
                res.json = (obj) => {
                  if (!responseHeaders['content-type']) {
                    res.set('content-type', 'application/json')
                  }
                  responseBody = Utils.toArray(JSON.stringify(obj), 'utf8')
                  buildResponse()
                }

                res.__text = res.text
                res.text = (str) => {
                  if (!responseHeaders['content-type']) {
                    res.set('content-type', 'text/plain')
                  }
                  responseBody = Utils.toArray(str, 'utf8')
                  buildResponse()
                }

                res.__end = res.end
                res.end = () => {
                  buildResponse()
                }

                res.__sendFile = res.sendFile
                res.sendFile = (path, options, callback) => {
                  fs.readFile(path, (err, data) => {
                    if (err) {
                      if (callback) return callback(err)
                      res.status(500)
                      return buildResponse()
                    }

                    const mimeType = mime.lookup(path) || 'application/octet-stream'
                    res.set('Content-Type', mimeType)
                    responseBody = Array.from(data)
                    buildResponse()
                  })
                }

                // Add sendCertificateRequest handler
                res.sendCertificateRequest = async (certsToRequest: RequestedCertificateSet, identityKey: string) => {
                  if (this.openNonGeneralHandles[identityKey]) {
                    this.openNonGeneralHandles[identityKey].push(res)
                  } else {
                    this.openNonGeneralHandles[identityKey] = [res]
                  }
                  await this.peer?.requestCertificates(certsToRequest, identityKey)
                }

                if (this.peer?.certificatesToRequest?.certifiers?.length) {
                  this.openNextHandlers[senderPublicKey] = next
                } else {
                  next()
                }
              }
            } catch (error) {
              next(error)
            }
          })

          if (this.messageCallback) {
            // Note: The requester may want more detailed error handling
            this.messageCallback(message)
              .catch((err) => {
                console.error(err)
                return res.status(500).json({
                  status: 'error',
                  code: 'ERR_INTERNAL_SERVER_ERROR',
                  description: err.message || 'An unknown error occurred.'
                })
              })
          }
        } else {
          // No auth headers
          if (this.allowAuthenticated) {
            req.auth = { identityKey: 'unknown' }
            next()
          } else {
            res.status(401).json({
              status: 'error',
              code: 'UNAUTHORIZED',
              message: 'Mutual-authentication failed!'
            })
          }
        }
      }
    } catch (error) {
      next(error)
    }
  }

  private resetRes(res: Response): Response {
    res.status = (res as any).__status
    res.set = res.__set
    res.json = res.__json
    res.text = res.__text
    res.send = res.__send
    res.end = res.__end
    res.sendFile = res.__sendFile
    return res
  }
}

// Helper: Build AuthMessage from Request
function buildAuthMessageFromRequest(req: Request): AuthMessage {
  const writer = new Utils.Writer()
  const requestNonce = req.headers['x-bsv-auth-request-id']
  const requestNonceBytes = requestNonce ? Utils.toArray(requestNonce, 'base64') : []
  writer.write(requestNonceBytes)
  writer.writeVarIntNum(req.method.length)
  writer.write(Utils.toArray(req.method))

  // Dynamically determine the base URL
  const protocol = req.protocol // Ex. 'http' or 'https'
  const host = req.get('host') // Ex. 'example.com:3000'
  const baseUrl = `${protocol}://${host}`
  const parsedUrl = new URL(`${baseUrl}${req.originalUrl}`)

  // Pathname
  if (parsedUrl.pathname.length > 0) {
    const pathnameAsArray = Utils.toArray(parsedUrl.pathname)
    writer.writeVarIntNum(pathnameAsArray.length)
    writer.write(pathnameAsArray)
  } else {
    writer.writeVarIntNum(-1)
  }

  // Search
  if (parsedUrl.search.length > 0) {
    const searchAsArray = Utils.toArray(parsedUrl.search)
    writer.writeVarIntNum(searchAsArray.length)
    writer.write(searchAsArray)
  } else {
    writer.writeVarIntNum(-1)
  }

  // Headers
  const includedHeaders: [string, string][] = []
  for (let [k, v] of Object.entries(req.headers)) {
    k = k.toLowerCase()
    if ((k.startsWith('x-bsv-') || k === 'content-type' || k === 'authorization') && !k.startsWith('x-bsv-auth')) {
      includedHeaders.push([k, v as string])
    }
  }

  writer.writeVarIntNum(includedHeaders.length)
  for (let i = 0; i < includedHeaders.length; i++) {
    const headerKeyAsArray = Utils.toArray(includedHeaders[i][0], 'utf8')
    writer.writeVarIntNum(headerKeyAsArray.length)
    writer.write(headerKeyAsArray)

    const headerValueAsArray = Utils.toArray(includedHeaders[i][1], 'utf8')
    writer.writeVarIntNum(headerValueAsArray.length)
    writer.write(headerValueAsArray)
  }

  // Body
  writeBodyToWriter(req, writer)

  return {
    messageType: 'general',
    version: req.headers['x-bsv-auth-version'],
    identityKey: req.headers['x-bsv-auth-identity-key'],
    nonce: req.headers['x-bsv-auth-nonce'],
    yourNonce: req.headers['x-bsv-auth-your-nonce'],
    payload: writer.toArray(),
    signature: req.headers['x-bsv-auth-signature'] ? Utils.toArray(req.headers['x-bsv-auth-signature'], 'hex') : []
  }
}

// Helper: Write body to writer
function writeBodyToWriter(req: Request, writer: Utils.Writer) {
  const { body, headers } = req

  if (Array.isArray(body) && body.every((item) => typeof item === 'number')) {
    // If the body is already a number[]
    writer.writeVarIntNum(body.length)
    writer.write(body)
  } else if (body instanceof Uint8Array) {
    // If the body is a Uint8Array
    writer.writeVarIntNum(body.length)
    writer.write(Array.from(body)) // Convert Uint8Array to number[]
  } else if (headers['content-type'] === 'application/json' && body && Object.keys(body).length > 0) {
    // If the body is JSON
    const bodyAsArray = Utils.toArray(JSON.stringify(body), 'utf8')
    writer.writeVarIntNum(bodyAsArray.length)
    writer.write(bodyAsArray)
  } else if (headers['content-type'] === 'application/x-www-form-urlencoded' && body && Object.keys(body).length > 0) {
    // If the body is URL-encoded
    const parsedBody = new URLSearchParams(body).toString()
    const bodyAsArray = Utils.toArray(parsedBody, 'utf8')
    writer.writeVarIntNum(bodyAsArray.length)
    writer.write(bodyAsArray)
  } else if (headers['content-type'] === 'text/plain' && typeof body === 'string' && body.length > 0) {
    // If the body is plain text
    const bodyAsArray = Utils.toArray(body, 'utf8')
    writer.writeVarIntNum(bodyAsArray.length)
    writer.write(bodyAsArray)
  } else {
    // No valid body
    writer.writeVarIntNum(-1)
  }
}

// Helper: Build response payload for sending back to peer
function buildResponsePayload(requestId: string, responseStatus: number, responseHeaders: Record<string, any>, responseBody: number[], req: Request): number[] {
  const writer = new Utils.Writer()
  writer.write(Utils.toArray(requestId, 'base64'))
  writer.writeVarIntNum(responseStatus)

  const includedHeaders: [string, string][] = []
  // Define an explicit order by sorting keys to ensure client/server sign headers in the same order.
  const sortedKeys = Object.keys(responseHeaders)
    .filter(k => k.toLowerCase().startsWith('x-bsv-') || k.toLowerCase() === 'authorization')
    .sort((keyA, keyB) => keyA.localeCompare(keyB))

  for (const k of sortedKeys) {
    const lowerKey = k.toLowerCase()
    if (!lowerKey.startsWith('x-bsv-auth')) {
      includedHeaders.push([lowerKey, responseHeaders[k]])
    }
  }

  writer.writeVarIntNum(includedHeaders.length)
  for (let i = 0; i < includedHeaders.length; i++) {
    const headerKeyAsArray = Utils.toArray(includedHeaders[i][0], 'utf8')
    writer.writeVarIntNum(headerKeyAsArray.length)
    writer.write(headerKeyAsArray)

    const headerValueAsArray = Utils.toArray(includedHeaders[i][1], 'utf8')
    writer.writeVarIntNum(headerValueAsArray.length)
    writer.write(headerValueAsArray)
  }

  if (responseBody.length > 0) {
    writer.writeVarIntNum(responseBody.length)
    writer.write(responseBody)
  } else {
    writer.writeVarIntNum(-1)
  }

  return writer.toArray()
}

// Helper: Convert values passed to res.send(...) into byte arrays
function convertValueToArray(val: any, responseHeaders: Record<string, any>): number[] {
  if (typeof val === 'string') {
    return Utils.toArray(val, 'utf8')
  } else if (val instanceof Buffer) {
    return Array.from(val)
  } else if (typeof val === 'object') {
    if (val !== null) {
      if (!responseHeaders['content-type']) {
        responseHeaders['content-type'] = 'application/json'
      }
      return Utils.toArray(JSON.stringify(val), 'utf8')
    }
  } else if (typeof val === 'number') {
    return Utils.toArray(val.toString(), 'utf8')
  } else {
    return Utils.toArray(String(val), 'utf8')
  }
  return []
}

export function createAuthMiddleware(options: AuthMiddlewareOptions) {
  const transport = new ExpressTransport(options.allowUnauthenticated ?? false)
  const sessionManager = options.sessionManager || new SessionManager()

  if (!options.wallet) {
    throw new Error('You must configure the auth middleware with a wallet.')
  }

  const wallet = options.wallet
  const peer = new Peer(wallet, transport, options.certificatesToRequest, sessionManager)
  transport.setPeer(peer)

  // Return the express middleware
  return (req: Request, res: Response, next: NextFunction) => {
    transport.handleIncomingRequest(req, res, next, options.onCertificatesReceived)
  }
}