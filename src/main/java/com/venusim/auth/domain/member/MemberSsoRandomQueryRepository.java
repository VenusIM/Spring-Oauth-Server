package com.venusim.auth.domain.member;

import com.querydsl.jpa.impl.JPAQueryFactory;
import com.venusim.auth.domain.member.QMemberSsoRandomEntity;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

// 복잡한 쿼리가 필요할 경우 QueryDSL 활용
@Repository
public class MemberSsoRandomQueryRepository {

    private final JPAQueryFactory query;

    public MemberSsoRandomQueryRepository(JPAQueryFactory query) {
        this.query = query;
    }

    public boolean existsValid(String idMember, String code, LocalDateTime threshold) {
        QMemberSsoRandomEntity m = QMemberSsoRandomEntity.memberSsoRandomEntity;
        Integer result = query
                .selectOne()
                .from(m)
                .where(
                    m.idMember.eq(idMember),
                    m.coedRandom.eq(code),
                    m.datePermission.after(threshold)
                )
                .fetchFirst();
        return result != null;
    }
}
