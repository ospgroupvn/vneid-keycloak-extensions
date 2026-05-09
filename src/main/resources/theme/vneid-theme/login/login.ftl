<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('summary') displayInfo=(realm.password && realm.registrationAllowed && !registrationDisabled??); section>
    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "socialProviders" >
        <#if realm.password && social.providers??>
            <div id="kc-social-providers" class="${properties.kcFormSocialAccountSectionClass!}">
                <hr/>
                <h4>${msg("identity-provider-login-label")}</h4>
                <ul class="${properties.kcFormSocialAccountSectionClass!} list-none p-0">
                    <#list social.providers as p>
                        <#if p.alias?has_content && p.alias == "vneid">
                            <li>
                                <a id="social-vneid" class="${properties.kcFormSocialAccountLinkClass!} vneid-login-btn"
                                   href="${p.loginUrl}"
                                   role="button"
                                   aria-label="${msg("vneid.login.button")}">
                                    <img src="${url.resourcesPath}/img/vneid-logo.png"
                                         alt="VNeID"
                                         class="vneid-logo"
                                         loading="lazy"
                                         aria-hidden="true"/>
                                    <span class="vneid-btn-text">${msg("vneid.login.button")}</span>
                                </a>
                            </li>
                        <#else>
                            <li>
                                <a id="social-${p.alias}" class="${properties.kcFormSocialAccountLinkClass!}"
                                   href="${p.loginUrl}">
                                    ${p.displayName}
                                </a>
                            </li>
                        </#if>
                    </#list>
                </ul>
            </div>
        </#if>
    </#if>
</@layout.registrationLayout>
