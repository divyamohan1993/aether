// Common error types thrown by the TM module. Mapped to HTTP status by
// router.js. Shape matches the public error contract:
// { error: { code, message } }.

export class ApiError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status || 400;
  }
}

export class ScopeError extends ApiError {
  constructor(code, message) {
    super(code, message || 'Out of scope.', 403);
    this.name = 'ScopeError';
  }
}

export class NotFoundError extends ApiError {
  constructor(code, message) {
    super(code, message || 'Not found.', 404);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends ApiError {
  constructor(code, message) {
    super(code, message || 'Conflict.', 409);
    this.name = 'ConflictError';
  }
}
