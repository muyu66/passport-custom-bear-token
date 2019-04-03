export declare class CustomBearTokenStrategy {
    // 使用时, 用不同的类继承本类, 覆写name属性, 即可
    name: string;
    // 覆写TOKEN属性
    token: string;
    // 覆写支持的授权方法
    supports: string[];
    // 覆写未授权异常
    error: any;
    // 覆写属性, 确认请求的token KEY, 一般为 authorization, 或 token
    tokenSign: string;
}
