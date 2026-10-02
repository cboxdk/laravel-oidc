<?php

declare(strict_types=1);

namespace Cbox\Oidc\Http;

/**
 * The methods the protocol needs: GET for documents, POST for forms.
 */
enum HttpMethod: string
{
    case Get = 'GET';
    case Post = 'POST';
}
