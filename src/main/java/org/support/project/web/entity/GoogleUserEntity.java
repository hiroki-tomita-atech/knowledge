package org.support.project.web.entity;

public class GoogleUserEntity {
    private String email;
    private String familyName;
    private String givenName;
    private String hd;
    private String id;
    private String name;
    private String picture;
    private boolean verifiedEmail;

    public GoogleUserEntity(String email, String familyName, String givenName, String hd, String id,
        String name, String picture, boolean verifiedEmail) {
        this.email = email;
        this.familyName = familyName;
        this.givenName = givenName;
        this.hd = hd;
        this.id = id;
        this.name = name;
        this.picture = picture;
        this.verifiedEmail = verifiedEmail;
    }

    public String getEmail() {
        return this.email;
    }

    public String getFamilyName() {
        return this.familyName;
    }

    public String getGivenName() {
        return this.givenName;
    }

    public String getHd() {
        return this.hd;
    }

    public String getId() {
        return this.id;
    }

    public String getName() {
        return this.name;
    }

    public void setEmail(String email) {
        this.email = email;
    }


}