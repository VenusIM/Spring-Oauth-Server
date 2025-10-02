package com.venusim.auth.domain.member;

import jakarta.persistence.*;
import org.hibernate.annotations.Comment;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "member_sso_random",
        indexes = {
                @Index(name = "ix-member_sso_random", columnList = "date_permission DESC, coed_random, id_member")
        }
)
public class MemberSsoRandomEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "no_seq", nullable = false, updatable = false)
    @Comment("일련번호")
    private Long noSeq;

    @Column(name = "id_member", length = 20, nullable = false)
    @Comment("회원ID")
    private String idMember;

    @Column(name = "coed_random", length = 16, nullable = false)
    @Comment("랜덤코드")
    private String coedRandom;

    @Column(name = "date_insert", nullable = false,
            columnDefinition = "datetime default CURRENT_TIMESTAMP")
    @Comment("등록일")
    private LocalDateTime dateInsert;

    @Column(name = "date_permission", nullable = false)
    @Comment("허용일")
    private LocalDateTime datePermission;

    @Column(name = "ip", length = 20, nullable = false)
    @Comment("접속 IP")
    private String ip;

    @Column(name = "type_device", length = 2, nullable = false)
    @Comment("장치구분 : mo.모바일, pc.PC")
    private String typeDevice;

    @Column(name = "name_browser", length = 30)
    @Comment("접속 브라우저(30자리만 짤라 써도 구별 될 듯)")
    private String nameBrowser;

    protected MemberSsoRandomEntity() { /* JPA 기본 생성자 */ }

    public MemberSsoRandomEntity(String idMember, String coedRandom,
                                 LocalDateTime dateInsert, LocalDateTime datePermission,
                                 String ip, String typeDevice, String nameBrowser) {
        this.idMember = idMember;
        this.coedRandom = coedRandom;
        this.dateInsert = dateInsert;
        this.datePermission = datePermission;
        this.ip = ip;
        this.typeDevice = typeDevice;
        this.nameBrowser = nameBrowser;
    }


    public Long getNoSeq() { return noSeq; }
    public String getIdMember() { return idMember; }
    public void setIdMember(String idMember) { this.idMember = idMember; }

    public String getCoedRandom() { return coedRandom; }
    public void setCoedRandom(String coedRandom) { this.coedRandom = coedRandom; }

    public LocalDateTime getDateInsert() { return dateInsert; }
    public void setDateInsert(LocalDateTime dateInsert) { this.dateInsert = dateInsert; }

    public LocalDateTime getDatePermission() { return datePermission; }
    public void setDatePermission(LocalDateTime datePermission) { this.datePermission = datePermission; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getTypeDevice() { return typeDevice; }
    public void setTypeDevice(String typeDevice) { this.typeDevice = typeDevice; }

    public String getNameBrowser() { return nameBrowser; }
    public void setNameBrowser(String nameBrowser) { this.nameBrowser = nameBrowser; }

    @Override
    public String toString() {
        return "MemberSsoRandomEntity{" +
                "noSeq=" + noSeq +
                ", idMember='" + idMember + '\'' +
                ", coedRandom='" + coedRandom + '\'' +
                ", dateInsert=" + dateInsert +
                ", datePermission=" + datePermission +
                ", ip='" + ip + '\'' +
                ", typeDevice='" + typeDevice + '\'' +
                ", nameBrowser='" + nameBrowser + '\'' +
                '}';
    }
}
