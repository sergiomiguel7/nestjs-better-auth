'use strict';

const common = require('@nestjs/common');
const graphql = require('@nestjs/graphql');
const core = require('@nestjs/core');
const websockets = require('@nestjs/websockets');
const node = require('better-auth/node');
const plugins = require('better-auth/plugins');
const express = require('express');

function _interopNamespaceCompat(e) {
	if (e && typeof e === 'object' && 'default' in e) return e;
	const n = Object.create(null);
	if (e) {
		for (const k in e) {
			n[k] = e[k];
		}
	}
	n.default = e;
	return n;
}

const express__namespace = /*#__PURE__*/_interopNamespaceCompat(express);

const BEFORE_HOOK_KEY = Symbol("BEFORE_HOOK");
const AFTER_HOOK_KEY = Symbol("AFTER_HOOK");
const HOOK_KEY = Symbol("HOOK");
const AUTH_MODULE_OPTIONS_KEY = Symbol("AUTH_MODULE_OPTIONS");
const DATABASE_HOOK_KEY = Symbol("DATABASE_HOOK");
const DATABASE_HOOK_METADATA_KEY = Symbol(
  "DATABASE_HOOK_METADATA"
);

function getRequestFromContext(context) {
  const contextType = context.getType();
  if (contextType === "graphql") {
    return graphql.GqlExecutionContext.create(context).getContext().req;
  }
  if (contextType === "ws") {
    return context.switchToWs().getClient();
  }
  return context.switchToHttp().getRequest();
}

const AllowAnonymous = () => common.SetMetadata("PUBLIC", true);
const OptionalAuth = () => common.SetMetadata("OPTIONAL", true);
const Roles = (roles) => common.SetMetadata("ROLES", roles);
const Public = AllowAnonymous;
const Optional = OptionalAuth;
const Session = common.createParamDecorator((_data, context) => {
  const request = getRequestFromContext(context);
  return request.session;
});
const BeforeHook = (path) => common.SetMetadata(BEFORE_HOOK_KEY, path);
const AfterHook = (path) => common.SetMetadata(AFTER_HOOK_KEY, path);
const Hook = () => common.SetMetadata(HOOK_KEY, true);
const DatabaseHook = () => common.SetMetadata(DATABASE_HOOK_KEY, true);
function createDatabaseHookDecorator(stage) {
  return function databaseHookDecorator(model, operation) {
    const decorator = (target, propertyKey, descriptor) => {
      const handler = descriptor?.value;
      if (!handler) {
        throw new Error(
          `@${stage === "before" ? "Before" : "After"}DatabaseHook can only be applied to methods`
        );
      }
      const metadata = {
        model,
        operation,
        stage
      };
      Reflect.defineMetadata(DATABASE_HOOK_METADATA_KEY, metadata, handler);
      if (propertyKey !== void 0) {
        Reflect.defineMetadata(
          DATABASE_HOOK_METADATA_KEY,
          metadata,
          target,
          propertyKey
        );
      }
      return descriptor;
    };
    return decorator;
  };
}
const BeforeDatabaseHook = createDatabaseHookDecorator("before");
const AfterDatabaseHook = createDatabaseHookDecorator("after");

const MODULE_OPTIONS_TOKEN = Symbol("AUTH_MODULE_OPTIONS");
const { ConfigurableModuleClass, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } = new common.ConfigurableModuleBuilder({
  optionsInjectionToken: MODULE_OPTIONS_TOKEN
}).setClassMethodName("forRoot").setExtras(
  {
    isGlobal: true,
    disableTrustedOriginsCors: false,
    disableBodyParser: false,
    disableGlobalAuthGuard: false
  },
  (def, extras) => {
    return {
      ...def,
      exports: [MODULE_OPTIONS_TOKEN],
      global: extras.isGlobal
    };
  }
).build();

var __getOwnPropDesc$2 = Object.getOwnPropertyDescriptor;
var __decorateClass$2 = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc$2(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam$2 = (index, decorator) => (target, key) => decorator(target, key, index);
exports.AuthService = class AuthService {
  constructor(options) {
    this.options = options;
  }
  /**
   * Returns the API endpoints provided by the auth instance
   */
  get api() {
    return this.options.auth.api;
  }
  /**
   * Returns the complete auth instance
   * Access this for plugin-specific functionality
   */
  get instance() {
    return this.options.auth;
  }
};
exports.AuthService = __decorateClass$2([
  __decorateParam$2(0, common.Inject(MODULE_OPTIONS_TOKEN))
], exports.AuthService);

var __getOwnPropDesc$1 = Object.getOwnPropertyDescriptor;
var __decorateClass$1 = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc$1(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam$1 = (index, decorator) => (target, key) => decorator(target, key, index);
const AuthContextErrorMap = {
  http: {
    UNAUTHORIZED: (args) => new common.UnauthorizedException(
      args ?? {
        code: "UNAUTHORIZED",
        message: "Unauthorized"
      }
    ),
    FORBIDDEN: (args) => new common.ForbiddenException(
      args ?? {
        code: "FORBIDDEN",
        message: "Insufficient permissions"
      }
    )
  },
  ws: {
    UNAUTHORIZED: (args) => new websockets.WsException(args ?? "UNAUTHORIZED"),
    FORBIDDEN: (args) => new websockets.WsException(args ?? "FORBIDDEN")
  },
  rpc: {
    UNAUTHORIZED: () => new Error("UNAUTHORIZED"),
    FORBIDDEN: () => new Error("FORBIDDEN")
  },
  graphql: {}
};
AuthContextErrorMap.graphql = AuthContextErrorMap.http;
exports.AuthGuard = class AuthGuard {
  constructor(reflector, options) {
    this.reflector = reflector;
    this.options = options;
  }
  /**
   * Validates if the current request is authenticated
   * Attaches session and user information to the request object
   * Supports HTTP, GraphQL and WebSocket execution contexts
   * @param context - The execution context of the current request
   * @returns True if the request is authorized to proceed, throws an error otherwise
   */
  async canActivate(context) {
    const request = getRequestFromContext(context);
    const session = await this.options.auth.api.getSession({
      headers: node.fromNodeHeaders(
        request.headers || request?.handshake?.headers || []
      )
    });
    request.session = session;
    request.user = session?.user ?? null;
    const isPublic = this.reflector.getAllAndOverride("PUBLIC", [
      context.getHandler(),
      context.getClass()
    ]);
    if (isPublic) return true;
    const isOptional = this.reflector.getAllAndOverride("OPTIONAL", [
      context.getHandler(),
      context.getClass()
    ]);
    if (isOptional && !session) return true;
    const ctxType = context.getType() ?? "http";
    const errorFactory = AuthContextErrorMap[ctxType] ?? AuthContextErrorMap.http;
    if (!session) throw errorFactory.UNAUTHORIZED();
    const requiredRoles = this.reflector.getAllAndOverride("ROLES", [
      context.getHandler(),
      context.getClass()
    ]);
    if (requiredRoles && requiredRoles.length > 0) {
      const userRole = session.user.role;
      let hasRole = false;
      if (Array.isArray(userRole)) {
        hasRole = userRole.some((role) => requiredRoles.includes(role));
      } else if (typeof userRole === "string") {
        hasRole = userRole.split(",").some((role) => requiredRoles.includes(role));
      }
      if (!hasRole) throw errorFactory.FORBIDDEN();
    }
    return true;
  }
};
exports.AuthGuard = __decorateClass$1([
  common.Injectable(),
  __decorateParam$1(0, common.Inject(core.Reflector)),
  __decorateParam$1(1, common.Inject(MODULE_OPTIONS_TOKEN))
], exports.AuthGuard);

function SkipBodyParsingMiddleware(basePath = "/api/auth") {
  return (req, res, next) => {
    if (req.baseUrl.startsWith(basePath)) {
      next();
      return;
    }
    express__namespace.json()(req, res, (err) => {
      if (err) {
        next(err);
        return;
      }
      express__namespace.urlencoded({ extended: true })(req, res, next);
    });
  };
}

var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __decorateClass = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam = (index, decorator) => (target, key) => decorator(target, key, index);
const HOOKS = [
  { metadataKey: BEFORE_HOOK_KEY, hookType: "before" },
  { metadataKey: AFTER_HOOK_KEY, hookType: "after" }
];
exports.AuthModule = class AuthModule extends ConfigurableModuleClass {
  constructor(discoveryService, metadataScanner, adapter, options) {
    super();
    this.discoveryService = discoveryService;
    this.metadataScanner = metadataScanner;
    this.adapter = adapter;
    this.options = options;
  }
  logger = new common.Logger(exports.AuthModule.name);
  onApplicationBootstrap() {
    const providers = this.discoveryService.getProviders().filter(
      ({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype)
    );
    const databaseHookProviders = this.discoveryService.getProviders().filter(
      ({ metatype }) => metatype && Reflect.getMetadata(DATABASE_HOOK_KEY, metatype)
    );
    const hasHookProviders = providers.length > 0;
    const hasDatabaseHookProviders = databaseHookProviders.length > 0;
    const hooksConfigured = typeof this.options.auth?.options?.hooks === "object";
    const databaseHooksConfigured = typeof this.options.auth?.options?.databaseHooks === "object";
    if (hasHookProviders && !hooksConfigured)
      throw new Error(
        "Detected @Hook providers but Better Auth 'hooks' are not configured. Add 'hooks: {}' to your betterAuth(...) options."
      );
    if (hasDatabaseHookProviders && !databaseHooksConfigured)
      throw new Error(
        "Detected @DatabaseHook providers but Better Auth 'databaseHooks' are not configured. Add 'databaseHooks: {}' to your betterAuth(...) options."
      );
    if (hooksConfigured) {
      for (const provider of providers) {
        if (!provider.instance) continue;
        const providerPrototype = Object.getPrototypeOf(provider.instance);
        const methods = this.metadataScanner.getAllMethodNames(providerPrototype);
        for (const method of methods) {
          const providerMethod = providerPrototype[method];
          this.setupHooks(providerMethod, provider.instance);
        }
      }
    }
    if (!databaseHooksConfigured) return;
    for (const provider of databaseHookProviders) {
      if (!provider.instance) continue;
      const providerPrototype = Object.getPrototypeOf(provider.instance);
      const methods = this.metadataScanner.getAllMethodNames(providerPrototype);
      for (const method of methods) {
        const providerMethod = providerPrototype[method];
        this.setupDatabaseHooks(providerMethod, provider.instance, method);
      }
    }
  }
  configure(consumer) {
    const trustedOrigins = this.options.auth.options.trustedOrigins;
    const isNotFunctionBased = trustedOrigins && Array.isArray(trustedOrigins);
    if (!this.options.disableTrustedOriginsCors && isNotFunctionBased) {
      this.adapter.httpAdapter.enableCors({
        origin: trustedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true
      });
    } else if (trustedOrigins && !this.options.disableTrustedOriginsCors && !isNotFunctionBased)
      throw new Error(
        "Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true."
      );
    let basePath = this.options.auth.options.basePath ?? "/api/auth";
    if (!basePath.startsWith("/")) {
      basePath = `/${basePath}`;
    }
    if (basePath.endsWith("/")) {
      basePath = basePath.slice(0, -1);
    }
    if (!this.options.disableBodyParser) {
      consumer.apply(SkipBodyParsingMiddleware(basePath)).forRoutes("*path");
    }
    const handler = node.toNodeHandler(this.options.auth);
    this.adapter.httpAdapter.getInstance().use(`${basePath}/*path`, (req, res) => {
      return handler(req, res);
    });
    this.logger.log(`AuthModule initialized BetterAuth on '${basePath}/*'`);
  }
  setupHooks(providerMethod, providerClass) {
    if (!this.options.auth.options.hooks) return;
    for (const { metadataKey, hookType } of HOOKS) {
      const hasHook = Reflect.hasMetadata(metadataKey, providerMethod);
      if (!hasHook) continue;
      const hookPath = Reflect.getMetadata(metadataKey, providerMethod);
      const originalHook = this.options.auth.options.hooks[hookType];
      this.options.auth.options.hooks[hookType] = plugins.createAuthMiddleware(
        async (ctx) => {
          if (originalHook) {
            await originalHook(ctx);
          }
          if (hookPath && hookPath !== ctx.path) return;
          await providerMethod.apply(providerClass, [ctx]);
        }
      );
    }
  }
  setupDatabaseHooks(providerMethod, providerInstance, methodName) {
    const databaseHooks = this.options.auth.options.databaseHooks;
    if (!databaseHooks) return;
    const metadata = this.getDatabaseHookMetadata(
      providerMethod,
      providerInstance,
      methodName
    );
    if (!metadata) return;
    const { model, operation, stage } = metadata;
    if (!databaseHooks[model]) {
      databaseHooks[model] = {};
    }
    const modelHooks = databaseHooks[model];
    if (!modelHooks[operation]) {
      modelHooks[operation] = {};
    }
    const operationHooks = modelHooks[operation];
    if (stage === "before") {
      const originalHook2 = operationHooks.before;
      const boundProviderMethod2 = providerMethod.bind(
        providerInstance
      );
      operationHooks.before = this.composeBeforeDatabaseHook(
        originalHook2,
        boundProviderMethod2
      );
      return;
    }
    const originalHook = operationHooks.after;
    const boundProviderMethod = providerMethod.bind(
      providerInstance
    );
    operationHooks.after = this.composeAfterDatabaseHook(
      originalHook,
      boundProviderMethod
    );
  }
  composeBeforeDatabaseHook(originalHook, providerMethod) {
    return async (data, ctx) => {
      let payload = data;
      let previousResult;
      if (originalHook) {
        const originalResult = await originalHook(data, ctx);
        if (originalResult === false) return false;
        if (this.isDatabaseHookDataResult(originalResult)) {
          payload = originalResult.data;
          previousResult = originalResult;
        } else if (originalResult !== void 0) {
          return originalResult;
        }
      }
      const providerResult = await providerMethod(payload, ctx);
      if (providerResult === false) return false;
      if (this.isDatabaseHookDataResult(providerResult)) {
        return providerResult;
      }
      if (providerResult !== void 0) {
        return providerResult;
      }
      return previousResult;
    };
  }
  composeAfterDatabaseHook(originalHook, providerMethod) {
    return async (data, ctx) => {
      if (originalHook) {
        await originalHook(data, ctx);
      }
      await providerMethod(data, ctx);
    };
  }
  getDatabaseHookMetadata(providerMethod, providerInstance, methodName) {
    const direct = Reflect.getMetadata(
      DATABASE_HOOK_METADATA_KEY,
      providerMethod
    );
    if (direct) return direct;
    if (!methodName) return void 0;
    const prototype = Object.getPrototypeOf(providerInstance);
    return Reflect.getMetadata(
      DATABASE_HOOK_METADATA_KEY,
      prototype,
      methodName
    );
  }
  isDatabaseHookDataResult(result) {
    return typeof result === "object" && result !== null && "data" in result;
  }
  static forRootAsync(options) {
    const forRootAsyncResult = super.forRootAsync(options);
    return {
      ...super.forRootAsync(options),
      providers: [
        ...forRootAsyncResult.providers ?? [],
        ...!options.disableGlobalAuthGuard ? [
          {
            provide: core.APP_GUARD,
            useClass: exports.AuthGuard
          }
        ] : []
      ]
    };
  }
  static forRoot(arg1, arg2) {
    const normalizedOptions = typeof arg1 === "object" && arg1 !== null && "auth" in arg1 ? arg1 : { ...arg2 ?? {}, auth: arg1 };
    const forRootResult = super.forRoot(normalizedOptions);
    return {
      ...forRootResult,
      providers: [
        ...forRootResult.providers ?? [],
        ...!normalizedOptions.disableGlobalAuthGuard ? [
          {
            provide: core.APP_GUARD,
            useClass: exports.AuthGuard
          }
        ] : []
      ]
    };
  }
};
exports.AuthModule = __decorateClass([
  common.Module({
    imports: [core.DiscoveryModule],
    providers: [exports.AuthService],
    exports: [exports.AuthService]
  }),
  __decorateParam(0, common.Inject(core.DiscoveryService)),
  __decorateParam(1, common.Inject(core.MetadataScanner)),
  __decorateParam(2, common.Inject(core.HttpAdapterHost)),
  __decorateParam(3, common.Inject(MODULE_OPTIONS_TOKEN))
], exports.AuthModule);

exports.AFTER_HOOK_KEY = AFTER_HOOK_KEY;
exports.AUTH_MODULE_OPTIONS_KEY = AUTH_MODULE_OPTIONS_KEY;
exports.AfterDatabaseHook = AfterDatabaseHook;
exports.AfterHook = AfterHook;
exports.AllowAnonymous = AllowAnonymous;
exports.BEFORE_HOOK_KEY = BEFORE_HOOK_KEY;
exports.BeforeDatabaseHook = BeforeDatabaseHook;
exports.BeforeHook = BeforeHook;
exports.DATABASE_HOOK_KEY = DATABASE_HOOK_KEY;
exports.DATABASE_HOOK_METADATA_KEY = DATABASE_HOOK_METADATA_KEY;
exports.DatabaseHook = DatabaseHook;
exports.HOOK_KEY = HOOK_KEY;
exports.Hook = Hook;
exports.Optional = Optional;
exports.OptionalAuth = OptionalAuth;
exports.Public = Public;
exports.Roles = Roles;
exports.Session = Session;
