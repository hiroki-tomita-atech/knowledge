
package org.support.project.web.logic;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.support.project.web.bean.LoginedUser;
import org.support.project.web.entity.GoogleUserEntity;
import org.support.project.web.entity.TokenEntity;
import org.support.project.web.entity.UsersEntity;
import org.support.project.web.exception.AuthenticateException;

/**
 * Authentication
 * @author Koda
 * @param <T> type
 */
//@DI(impl=org.support.project.transparent.base.logic.impl.DefaultAuthenticationLogicImpl.class)
public interface AuthenticationLogic<T extends LoginedUser> {
    /**
     * OAuth2.0 を使った認証
     * @return url
     * @throws IOException
     */
    String authOAuth2() throws IOException;

    /**
     * 認可コードからアクセストークンを取得
     * @param code
     * @return token
     * @throws IOException
     */
    TokenEntity fetchTokenFromAuthCode(String code) throws IOException;

    /**
     * Google アカウント情報を取得
     * @param token
     * @return googleUser
     * @throws IOException
     */
    GoogleUserEntity fetchProfile(TokenEntity token) throws IOException;

    /**
     * 認証
     * @param userId userId
     * @param password password
     * @return result
     * @throws AuthenticateException AuthenticateException
     */
    int auth(String userId, String password) throws AuthenticateException;
    /**
     * ログインしているかどうか
     * @param request request
     * @return result
     * @throws AuthenticateException AuthenticateException
     */
    boolean isLogined(HttpServletRequest request) throws AuthenticateException;
    /**
     * セッションにログインしたユーザ情報を設定
     * @param userId userId
     * @param request request
     * @param response response
     * @throws AuthenticateException AuthenticateException
     */
    void setSession(String userId, HttpServletRequest request, HttpServletResponse response) throws AuthenticateException;
    /**
     * セッションに保持したユーザ情報を取得
     * @param request request
     * @return session
     * @throws AuthenticateException AuthenticateException
     */
    T getSession(HttpServletRequest request) throws AuthenticateException;;
    /**
     * 認可
     * @param request request
     * @return result
     * @throws AuthenticateException AuthenticateException
     */
    boolean isAuthorize(HttpServletRequest request) throws AuthenticateException;

    /**
     * セッションを破棄(ログアウト処理)
     * @param request request
     * @throws AuthenticateException AuthenticateException
     */
    void clearSession(HttpServletRequest request) throws AuthenticateException;


    /**
     * セッション情報を保持するCookieをセット
     * @param req HttpServletRequest
     * @param res HttpServletResponse
     * @throws AuthenticateException AuthenticateException
     */
    void setCookie(HttpServletRequest req, HttpServletResponse res) throws AuthenticateException;
    /**
     * Cookieからログイン
     * @param req HttpServletRequest
     * @param res HttpServletResponse
     * @return ログイン結果
     * @throws AuthenticateException AuthenticateException
     */
    boolean cookieLogin(HttpServletRequest req, HttpServletResponse res) throws AuthenticateException;

    /**
     * Cookieログインに使う情報の初期化
     * @param cookieMaxAge cookieMaxAge
     * @param cookieEncryptKey cookieEncryptKey
     * @param cookieSecure cookieSecure
     * @throws AuthenticateException AuthenticateException
     */
    void initCookie(int cookieMaxAge, String cookieEncryptKey, boolean cookieSecure) throws AuthenticateException;

    /**
     * Google アカウント情報でユーザ登録
     * @param googleUser
     * @return usersEntity
     */
    UsersEntity addUser(GoogleUserEntity googleUser);

    /**
     * メールアドレスからユーザを取得
     * @param email
     * @return usersEntity
     */
    UsersEntity getUserFromMail(String email);

    /**
     * ユーザキーからユーザを取得
     * @param key
     * @return usersEntity
     */
    UsersEntity getUserFromKey(String key);

    /**
     * ユーザを更新
     * @param user
     * @return usersEntity
     */
    UsersEntity updateUser(UsersEntity user);

}
