/**
 * @dnscontrol-auto-doc-comment language-reference/top-level-functions/FETCH.md
 */
declare function FETCH(
    url: string,
    init?: {
        method?:
            | 'GET'
            | 'POST'
            | 'PUT'
            | 'PATCH'
            | 'DELETE'
            | 'HEAD'
            | 'OPTIONS';
        headers?: { [key: string]: string };
        body?: string;
    }
): Promise<FetchResponse>;

interface FetchResponse {
    readonly ok: boolean;
    readonly status: number;
    readonly statusText: string;
    readonly url: string;
    readonly headers: ResponseHeaders;

    text(): Promise<string>;
    json(): Promise<any>;
}

interface ResponseHeaders {
    get(name: string): string;
    has(name: string): boolean;
}
