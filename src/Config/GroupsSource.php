<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

/**
 * Where a connection reads group memberships from.
 */
enum GroupsSource: string
{
    /** A claim of the verified ID token. */
    case IdToken = 'id_token';

    /** A claim of the userinfo response. */
    case UserInfo = 'userinfo';

    /** The provider sends no groups. */
    case None = 'none';
}
