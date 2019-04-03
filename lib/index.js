const Strategy = require('passport-strategy')

const tokenCookies = (req, sign = 'authorization') => {
    let token;
    if (req && req.cookies) {
        token = req.cookies[sign];
    }
    return token || '';
};
const tokenHeader = (req, sign = 'authorization') => {
    let token;
    if (req && req.headers) {
        token = req.headers[sign];
    }
    return token || '';
};
const tokenQuery = (req, sign = 'authorization') => {
    let token;
    if (req && req.query) {
        token = req.query[sign];
    }
    return token || '';
};
const tokenAuthHeader = (req, sign = 'authorization') => {
    let token;
    if (req && req.header) {
        token = req.headers[sign];
    }
    return token || '';
};

class CustomBearTokenStrategy extends Strategy {

    // 使用时, 用不同的类继承本类, 覆写name属性, 即可
    name = 'customBearToken';
    // 覆写TOKEN属性
    token = 'xxxxx';
    // 覆写支持的授权方法
    supports = ['tokenAuthHeader', 'tokenCookies', 'tokenHeader', 'tokenQuery'];
    // 覆写未授权异常
    error = new Error('未授权');
    // 覆写属性, 确认请求的token KEY, 一般为 authorization, 或 token
    tokenSign = 'authorization';

    _verify;

    constructor(verify) {
        super();
        if (!verify) {
            throw new TypeError('缺少回调');
        }
        this._verify = verify;
    }

    authenticate(req) {
        const self = this;
        function verified(err, user, info) {
            if (err) {
                return self.error(err);
            }
            if (!user) {
                return self.fail(info);
            }
            self.success(user, info);
        }
        try {
            this._verify(req, verified);
        } catch (ex) {
            return self.error(ex);
        }
    }

    // 如有必要, 可以覆写本方法
    validate(request, done) {
        const supports = [];
        if (supports.indexOf('tokenAuthHeader') >= 0) supports.push(tokenAuthHeader(request, tokenSign));
        if (supports.indexOf('tokenCookies') >= 0) supports.push(tokenCookies(request, tokenSign));
        if (supports.indexOf('tokenHeader') >= 0) supports.push(tokenHeader(request, tokenSign));
        if (supports.indexOf('tokenQuery') >= 0) supports.push(tokenQuery(request, tokenSign));

        const boolean = supports.indexOf(token) !== -1;
        if (!boolean) {
            return done(error, false);
        }
        done(null, boolean);
    }

}

module.exports.CustomBearTokenStrategy = CustomBearTokenStrategy;
